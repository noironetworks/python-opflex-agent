#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import copy
import netaddr
import os
import signal
import sys

from neutron.agent.common import config
from neutron.agent.dhcp import config as dhcp_config
from neutron.agent.linux import ip_lib
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import constants as n_constants
from neutron.common import eventlet_utils
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron.openstack.common import uuidutils
from neutron.plugins.openvswitch.agent import ovs_neutron_agent as ovs
from neutron.plugins.openvswitch.common import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

from opflexagent import as_metadata_manager
from opflexagent import constants as ofcst
from opflexagent import opflex_notify
from opflexagent import rpc
from opflexagent import snat_iptables_manager

eventlet_utils.monkey_patch()
LOG = logging.getLogger(__name__)

gbp_opts = [
    cfg.BoolOpt('hybrid_mode',
                default=False,
                help=_("Whether Neutron's ports can coexist with GBP owned"
                       "ports.")),
    cfg.StrOpt('epg_mapping_dir',
               default='/var/lib/opflex-agent-ovs/endpoints/',
               help=_("Directory where the EPG port mappings will be "
                      "stored.")),
    cfg.StrOpt('as_mapping_dir',
               default='/var/lib/opflex-agent-ovs/services/',
               help=_("Directory where the anycast svc mappings will be "
                      "stored.")),
    cfg.StrOpt('opflex_agent_dir',
               default='/var/lib/neutron/opflex_agent',
               help=_("Directory where the opflex agent state will be "
                      "stored.")),
    cfg.ListOpt('opflex_networks',
                default=['*'],
                help=_("List of the physical networks managed by this agent. "
                       "Use * for binding any opflex network to this agent")),
    cfg.ListOpt('internal_floating_ip_pool',
               default=['169.254.0.0/16'],
               help=_("IP pool used for intermediate floating-IPs with SNAT")),
    cfg.ListOpt('internal_floating_ip6_pool',
               default=['fe80::/64'],
               help=_("IPv6 pool used for intermediate floating-IPs "
                      "with SNAT"))
]
cfg.CONF.register_opts(gbp_opts, "OPFLEX")

FILE_EXTENSION = "ep"
FILE_NAME_FORMAT = "%s." + FILE_EXTENSION
VRF_FILE_EXTENSION = "rdconfig"
VRF_FILE_NAME_FORMAT = "%s." + VRF_FILE_EXTENSION
METADATA_DEFAULT_IP = '169.254.169.254'
METADATA_SUBNET = '169.254.0.0/16'


class GBPOvsPluginApi(rpc.GBPServerRpcApiMixin):
    pass


class ExtSegNextHopInfo(object):
    def __init__(self, es_name):
        self.es_name = es_name
        self.ip_start = None
        self.ip_end = None
        self.ip_gateway = None
        self.ip6_start = None
        self.ip6_end = None
        self.ip6_gateway = None
        self.next_hop_iface = None
        self.next_hop_mac = None
        self.from_config = False
        self.uuid = uuidutils.generate_uuid()

    def __str__(self):
        return ("%s: ipv4 (%s-%s,%s), ipv6 (%s-%s,%s), if %s, mac %s, (%s)" %
            (self.es_name, self.ip_start, self.ip_end, self.ip_gateway,
            self.ip6_start, self.ip6_end, self.ip6_gateway,
            self.next_hop_iface, self.next_hop_mac,
            "configured" if self.from_config else "auto-allocated"))

    def is_valid(self):
        return ((self.ip_start and self.ip_gateway) or
                (self.ip6_start and self.ip6_gateway))


class GBPOvsAgent(ovs.OVSNeutronAgent):

    def __init__(self, root_helper=None, **kwargs):
        self.hybrid_mode = kwargs['hybrid_mode']
        separator = (kwargs['epg_mapping_dir'][-1] if
                     kwargs['epg_mapping_dir'] else '')
        self.epg_mapping_file = (kwargs['epg_mapping_dir'] +
                                 ('/' if separator != '/' else '') +
                                 FILE_NAME_FORMAT)
        self.vrf_mapping_file = (kwargs['epg_mapping_dir'] +
                                 ('/' if separator != '/' else '') +
                                 VRF_FILE_NAME_FORMAT)
        self.file_formats = [self.epg_mapping_file,
                             self.vrf_mapping_file]
        self.opflex_networks = kwargs['opflex_networks']
        if self.opflex_networks and self.opflex_networks[0] == '*':
            self.opflex_networks = None
        self.int_fip_pool = {
            4: netaddr.IPSet(kwargs['internal_floating_ip_pool']),
            6: netaddr.IPSet(kwargs['internal_floating_ip6_pool'])}
        if METADATA_DEFAULT_IP in self.int_fip_pool[4]:
            self.int_fip_pool[4].remove(METADATA_DEFAULT_IP)
        self.int_fip_alloc = {4: {}, 6: {}}
        self._load_es_next_hop_info(kwargs['external_segment'])
        self.es_port_dict = {}
        self.vrf_dict = {}
        self.vif_to_vrf = {}
        self.updated_vrf = set()
        self.backup_updated_vrf = set()
        self.dhcp_domain = kwargs['dhcp_domain']
        self.root_helper = root_helper
        del kwargs['hybrid_mode']
        del kwargs['epg_mapping_dir']
        del kwargs['opflex_networks']
        del kwargs['internal_floating_ip_pool']
        del kwargs['internal_floating_ip6_pool']
        del kwargs['external_segment']
        del kwargs['dhcp_domain']

        self.notify_worker = opflex_notify.worker()
        super(GBPOvsAgent, self).__init__(**kwargs)
        self.supported_pt_network_types = [ofcst.TYPE_OPFLEX]
        self.setup_pt_directory()

    def setup_pt_directory(self):
        created = False
        for file_format in self.file_formats:
            directory = os.path.dirname(file_format)
            if not os.path.exists(directory):
                os.makedirs(directory)
                created = True
                continue
            # Remove all existing EPs mapping
            for f in os.listdir(directory):
                if f.endswith('.' + FILE_EXTENSION) or f.endswith(
                        '.' + VRF_FILE_EXTENSION):
                    try:
                        os.remove(os.path.join(directory, f))
                    except OSError as e:
                        LOG.debug(e.message)
        if not created:
            self.snat_iptables.cleanup_snat_all()

    def setup_rpc(self):
        self.agent_state['agent_type'] = ofcst.AGENT_TYPE_OPFLEX_OVS
        self.agent_state['configurations']['opflex_networks'] = (
            self.opflex_networks)
        self.agent_state['binary'] = 'opflex-ovs-agent'
        super(GBPOvsAgent, self).setup_rpc()
        # Set GBP rpc API
        self.of_rpc = GBPOvsPluginApi(rpc.TOPIC_OPFLEX)

        # Need to override the current RPC callbacks to add subnet related RPC
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE],
                     [constants.TUNNEL, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [topics.DVR, topics.UPDATE],
                     [topics.SUBNET, topics.UPDATE]]
        if self.l2_pop:
            consumers.append([topics.L2POPULATION,
                              topics.UPDATE, cfg.CONF.host])
        self.connection = agent_rpc.create_consumers(
            self.endpoints, self.topic, consumers, start_listening=False)

    def subnet_update(self, context, subnet):
        self.updated_vrf.add(subnet['tenant_id'])
        LOG.debug("subnet_update message processed for subnet %s",
                  subnet['id'])

    def _agent_has_updates(self, polling_manager):
        return (self.updated_vrf or
                super(GBPOvsAgent, self)._agent_has_updates(polling_manager))

    def _port_info_has_changes(self, port_info):
        return (port_info.get('vrf_updated') or
                super(GBPOvsAgent, self)._port_info_has_changes(port_info))

    def scan_ports(self, registered_ports, updated_ports=None):
        port_info = super(GBPOvsAgent, self).scan_ports(registered_ports,
                                                        updated_ports)
        self.backup_updated_vrf = self.updated_vrf
        self.updated_vrf = set()
        port_info['vrf_updated'] = self.backup_updated_vrf & set(
            self.vrf_dict.keys())
        return port_info

    def setup_integration_br(self):
        """Override parent setup integration bridge.

        The opflex agent controls all the flows in the integration bridge,
        therefore we have to make sure the parent doesn't reset them.
        """
        self.int_br.create()
        self.int_br.set_secure_mode()

        self.int_br.delete_port(cfg.CONF.OVS.int_peer_patch_port)
        # The following is executed in the parent method:
        # self.int_br.remove_all_flows()

        if self.hybrid_mode:
            # switch all traffic using L2 learning
            self.int_br.add_flow(priority=1, actions="normal")
        # Add a canary flow to int_br to track OVS restarts
        self.int_br.add_flow(table=constants.CANARY_TABLE, priority=0,
                             actions="drop")
        self.snat_iptables = snat_iptables_manager.SnatIptablesManager(
            self.int_br)

    def setup_physical_bridges(self, bridge_mappings):
        """Override parent setup physical bridges.

        Only needs to be executed in hybrid mode. If not in hybrid mode, only
        the existence of the integration bridge is assumed.
        """
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        if self.hybrid_mode:
            super(GBPOvsAgent, self).setup_physical_bridges(bridge_mappings)

    def reset_tunnel_br(self, tun_br_name=None):
        """Override parent reset tunnel br.

        Only needs to be executed in hybrid mode. If not in hybrid mode, only
        the existence of the integration bridge is assumed.
        """
        if self.hybrid_mode:
            super(GBPOvsAgent, self).reset_tunnel_br(tun_br_name)

    def setup_tunnel_br(self, tun_br_name=None):
        """Override parent setup tunnel br.

        Only needs to be executed in hybrid mode. If not in hybrid mode, only
        the existence of the integration bridge is assumed.
        """
        if self.hybrid_mode:
            super(GBPOvsAgent, self).setup_tunnel_br(tun_br_name)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner,
                   ovs_restarted):

        mapping = port.gbp_details
        if not mapping:
            self.mapping_cleanup(port.vif_id)
            if self.hybrid_mode:
                super(GBPOvsAgent, self).port_bound(
                    port, net_uuid, network_type, physical_network,
                    segmentation_id, fixed_ips, device_owner, ovs_restarted)
        elif network_type in self.supported_pt_network_types:
            # PT cleanup is needed before writing the new endpoint files
            self.mapping_cleanup(port.vif_id, cleanup_vrf=False)
            if ((self.opflex_networks is None) or
                    (physical_network in self.opflex_networks)):
                # Port has to be untagged due to a opflex agent requirement
                self.int_br.clear_db_attribute("Port", port.port_name, "tag")
                # Multiple files will be created based on how many MAC
                # addresses are owned by the specific port.
                mapping_copy = copy.deepcopy(mapping)
                mac_aap_map = {}
                mapping_copy['allowed_address_pairs'] = []
                mapping_copy['floating_ip'] = []
                fip_by_fixed = {}
                original_mac = mapping.get('mac_address') or port.vif_mac
                # Get extra details for main mac (if any)
                extra_details = mapping.get('extra_details', {}).get(
                    original_mac, {})
                # Prepare FIPs by fixed_ip
                for fip in (mapping.get('floating_ip', []) +
                            extra_details.get('floating_ip', [])):
                    fip_by_fixed.setdefault(
                        fip['fixed_ip_address'], []).append(fip)
                # For the main MAC, set floating IP collection to all those
                # FIPs pointing to the Port fixed ips.
                for fixed in (mapping.get('fixed_ips') or fixed_ips):
                    mapping_copy['floating_ip'].extend(
                        fip_by_fixed.get(fixed['ip_address'], []))
                # FIPs opinting to extra IPs
                for fixed in (mapping.get('extra_ips', []) +
                              extra_details.get('extra_ips', [])):
                    mapping_copy['floating_ip'].extend(
                        fip_by_fixed.get(fixed, []))

                if 'ip_mapping' in extra_details:
                    mapping_copy.setdefault('ip_mapping', []).extend(
                        extra_details.get('ip_mapping', []))
                if 'extra_ips' in extra_details:
                    mapping_copy.setdefault('extra_ips', []).extend(
                        extra_details.get('extra_ips', []))
                # For the main MAC EP, set al the AAP with no mac address or
                # MAC address equal to the original MAC.
                for aap in mapping.get('allowed_address_pairs', []):
                    if not aap.get('mac_address') or aap.get(
                            'mac_address') == original_mac:
                        # Should go with the MAIN mac address EP file
                        mapping_copy['allowed_address_pairs'].append(aap)
                        # Also set the right floating IPs
                        mapping_copy['floating_ip'].extend(
                            fip_by_fixed.get(aap['ip_address'], []))
                    else:
                        # Store for future processing
                        mac_aap_map.setdefault(
                            aap['mac_address'], []).append(aap)
                # Create mapping file for base MAC address
                self.mapping_to_file(port, net_uuid, mapping_copy, fixed_ips,
                                     device_owner)
                # Reset for AAP EP files
                mapping_copy['allowed_address_pairs'] = []
                mapping_copy['fixed_ips'] = []
                mapping_copy['subnets'] = []
                mapping_copy['enable_dhcp_optimization'] = False
                mapping_copy['enable_metadata_optimization'] = False
                mapping_copy['promiscuous_mode'] = False
                # Map to file based on the AAP with a MAC address
                for mac, aaps in mac_aap_map.iteritems():
                    # Get extra details for this mac (if any)
                    extra_details = mapping.get('extra_details', {}).get(mac,
                                                                         {})
                    # Replace the MAC address with the new one
                    mapping_copy['mac_address'] = mac
                    # The following info are only present if the MAC has at
                    # least one active address (server is doing the screening)
                    mapping_copy['floating_ip'] = extra_details.get(
                        'floating_ip', [])
                    mapping_copy['extra_ips'] = extra_details.get(
                        'extra_ips', [])
                    mapping_copy['ip_mapping'] = extra_details.get(
                        'ip_mapping', [])
                    # Extend the FIP list based on the allowed IPs
                    for aap in aaps:
                        mapping_copy['floating_ip'].extend(fip_by_fixed.get(
                            aap['ip_address'], []))
                    # For this mac, set all the allowed address pairs.
                    mapping_copy['allowed_address_pairs'] = aaps
                    self.mapping_to_file(port, net_uuid, mapping_copy, [],
                                         device_owner)
            else:
                LOG.error(_("Cannot provision OPFLEX network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        else:
            LOG.error(_("Network type %(net_type)s not supported for "
                        "Policy Target provisioning. Supported types: "
                        "%(supported)s"),
                      {'net_type': network_type,
                       'supported': self.supported_pt_network_types})

    def port_unbound(self, vif_id, net_uuid=None):
        super(GBPOvsAgent, self).port_unbound(vif_id, net_uuid)
        # Delete epg mapping file
        self.mapping_cleanup(vif_id)

    def port_dead(self, port):
        super(GBPOvsAgent, self).port_dead(port)
        # Delete epg mapping file
        self.mapping_cleanup(port.vif_id)

    def mapping_to_file(self, port, net_uuid, mapping, fixed_ips,
                        device_owner):
        """Mapping to file.

        Converts the port mapping into file.
        """
        # Skip router-interface ports - they interfere with OVS pipeline

        fixed_ips = mapping.get('fixed_ips') or fixed_ips
        if device_owner in [n_constants.DEVICE_OWNER_ROUTER_INTF]:
            return
        ips_ext = mapping.get('extra_ips') or []
        mac = mapping.get('mac_address') or port.vif_mac
        LOG.debug("Generating mapping for %s", port.vif_id + '_' + mac)
        mapping_dict = {
            "policy-space-name": mapping['ptg_tenant'],
            "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                    mapping['endpoint_group_name']),
            "interface-name": port.port_name,
            "promiscuous-mode": mapping.get('promiscuous_mode') or False,
            "uuid": '%s|%s' % (port.vif_id, mac.replace(':', '-')),
            'neutron-network': net_uuid}

        ips = [x['ip_address'] for x in fixed_ips]

        virtual_ips = []
        if device_owner == n_constants.DEVICE_OWNER_DHCP:
            # vm-name, if specified in mappings, will override this
            mapping_dict['attributes'] = {'vm-name': (
                'dhcp|' +
                mapping['ptg_tenant'] + '|' +
                mapping['app_profile_name'] + '|' +
                mapping['endpoint_group_name'])
            }
        else:
            if (mapping.get('enable_dhcp_optimization', False) and
               'subnets' in mapping):
                    self._map_dhcp_info(fixed_ips, mapping['subnets'],
                                        mapping_dict)
        for aap in mapping.get('allowed_address_pairs', []):
            if aap.get('ip_address'):
                virtual_ips.append(
                    {'ip': aap['ip_address'],
                     'mac': aap.get('mac_address', mac)})
                if aap.get('active'):
                    ips_ext.append(aap['ip_address'])
        if ips or ips_ext:
            mapping_dict['ip'] = sorted(ips + ips_ext)
            # Mac should only exist when the ip field is actually set
            mapping_dict['mac'] = mac
        if virtual_ips:
            mapping_dict['virtual-ip'] = sorted(virtual_ips,
                                                key=lambda x: x['ip'])

        if 'vm-name' in mapping:
            mapping_dict['attributes'] = {'vm-name': mapping['vm-name']}
        if 'vrf_name' in mapping:
            mapping_dict['domain-policy-space'] = mapping['vrf_tenant']
            mapping_dict['domain-name'] = mapping['vrf_name']
        if 'attestation' in mapping:
            mapping_dict['attestation'] = mapping['attestation']

        self._handle_host_snat_ip(mapping.get('host_snat_ips', []))
        self._fill_ip_mapping_info(port.vif_id, mac, mapping, ips + ips_ext,
                                   mapping_dict)
        # Create one file per MAC address.
        self._write_endpoint_file(port.vif_id + '_' + mac, mapping_dict)
        self.vrf_info_to_file(mapping, vif_id=port.vif_id)

    def vrf_info_to_file(self, mapping, vif_id=None):
        if 'vrf_subnets' in mapping:
            vrf_info = {
                'domain-policy-space': mapping['vrf_tenant'],
                'domain-name': mapping['vrf_name'],
                'internal-subnets': set(mapping['vrf_subnets'])}
            curr_vrf = self.vrf_dict.setdefault(
                mapping['l3_policy_id'], {'info': {}, 'vifs': set()})
            if curr_vrf['info'] != vrf_info:
                vrf_info_copy = copy.deepcopy(vrf_info)
                vrf_info_copy['internal-subnets'] = sorted(list(
                    vrf_info_copy['internal-subnets']) + [METADATA_SUBNET])
                self._write_vrf_file(mapping['l3_policy_id'], vrf_info_copy)
                curr_vrf['info'] = vrf_info
            if vif_id:
                curr_vrf['vifs'].add(vif_id)
                self.vif_to_vrf[vif_id] = mapping['l3_policy_id']

    def _map_dhcp_info(self, fixed_ips, subnets, mapping_dict):
        v4subnets = {k['id']: k for k in subnets
                     if k['ip_version'] == 4 and k['enable_dhcp']}
        v6subnets = {k['id']: k for k in subnets
                     if k['ip_version'] == 6 and k['enable_dhcp']}

        # REVISIT(amit): we use only the first fixed-ip for DHCP optimization
        for fip in fixed_ips:
            sn = v4subnets.get(fip['subnet_id'])
            if not sn:
                continue
            dhcp4 = {'ip': fip['ip_address'],
                     'routers': [x for x in [sn.get('gateway_ip')] if x],
                     'dns-servers': sn['dns_nameservers'],
                     'domain': self.dhcp_domain,
                     'prefix-len': netaddr.IPNetwork(sn['cidr']).prefixlen}
            dhcp4['static-routes'] = []
            for hr in sn['host_routes']:
                cidr = netaddr.IPNetwork(hr['destination'])
                dhcp4['static-routes'].append(
                    {'dest': str(cidr.network),
                     'dest-prefix': cidr.prefixlen,
                     'next-hop': hr['nexthop']})
            if 'dhcp_server_ips' in sn and sn['dhcp_server_ips']:
                dhcp4['server-ip'] = sn['dhcp_server_ips'][0]
            mapping_dict['dhcp4'] = dhcp4
            break
        if len(v6subnets) > 0 and v6subnets[0]['dns_nameservers']:
            mapping_dict['dhcp6'] = {
                'dns-servers': v6subnets[0]['dns_nameservers']}

    def mapping_cleanup(self, vif_id, cleanup_vrf=True):
        LOG.debug('Cleaning mapping for vif id %s', vif_id)
        self._delete_endpoint_files(vif_id)
        if cleanup_vrf:
            self._dissociate_port_from_es(vif_id)
            self._release_int_fip(4, vif_id)
            self._release_int_fip(6, vif_id)
        vrf_id = self.vif_to_vrf.get(vif_id)
        vrf = self.vrf_dict.get(vrf_id)
        if vrf and cleanup_vrf:
            del self.vif_to_vrf[vif_id]
            vrf['vifs'].discard(vif_id)
            if not vrf['vifs']:
                del self.vrf_dict[vrf_id]
                # No more endpoints for this VRF here
                self._delete_vrf_file(vrf_id)

    def process_network_ports(self, port_info, ovs_restarted):
        res = super(GBPOvsAgent, self).process_network_ports(port_info,
                                                             ovs_restarted)
        if port_info.get('vrf_updated'):
            try:
                vrf_details_list = self.of_rpc.get_vrf_details_list(
                    self.context, self.agent_id, port_info['vrf_updated'],
                    cfg.CONF.host)
                for details in vrf_details_list:
                    self.vrf_info_to_file(details)
            except Exception as e:
                LOG.error("VRF update failed because of %s", e.message)
                if self.backup_updated_vrf:
                    self.updated_vrf = self.backup_updated_vrf
                raise
        return res

    def treat_devices_added_or_updated(self, devices, ovs_restarted):
        # REVISIT(ivar): This method is copied from parent in order to inject
        # an efficient way to request GBP details. This is needed because today
        # ML2 RPC doesn't allow drivers to add custom information to the device
        # details list.

        skipped_devices = []
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                devices,
                self.agent_id,
                cfg.CONF.host)
            devices_gbp_details_list = self.of_rpc.get_gbp_details_list(
                self.context, self.agent_id, devices, cfg.CONF.host)
            # Correlate port details
            gbp_details_per_device = {x['device']: x for x in
                                      devices_gbp_details_list if x}
        except Exception as e:
            raise ovs.DeviceListRetrievalError(devices=devices, error=e)
        for details in devices_details_list:
            device = details['device']
            LOG.debug("Processing port: %s", device)
            port = self.int_br.get_vif_port_by_id(device)
            if not port:
                # The port disappeared and cannot be processed
                LOG.info(_("Port %s was not found on the integration bridge "
                           "and will therefore not be processed"), device)
                skipped_devices.append(device)
                continue

            gbp_details = gbp_details_per_device.get(details['device'], {})
            if gbp_details and 'port_id' not in gbp_details:
                # The port is dead
                details.pop('port_id', None)
            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                # Inject GBP details
                port.gbp_details = gbp_details
                self.treat_vif_port(port, details['port_id'],
                                    details['network_id'],
                                    details['network_type'],
                                    details['physical_network'],
                                    details['segmentation_id'],
                                    details['admin_state_up'],
                                    details['fixed_ips'],
                                    details['device_owner'],
                                    ovs_restarted)
                # update plugin about port status
                # FIXME(salv-orlando): Failures while updating device status
                # must be handled appropriately. Otherwise this might prevent
                # neutron server from sending network-vif-* events to the nova
                # API server, thus possibly preventing instance spawn.
                if details.get('admin_state_up'):
                    LOG.debug(_("Setting status for %s to UP"), device)
                    self.plugin_rpc.update_device_up(
                        self.context, device, self.agent_id, cfg.CONF.host)
                else:
                    LOG.debug(_("Setting status for %s to DOWN"), device)
                    self.plugin_rpc.update_device_down(
                        self.context, device, self.agent_id, cfg.CONF.host)
                LOG.info(_("Configuration for device %s completed."), device)
            else:
                LOG.warn(_("Device %s not defined on plugin"), device)
                if (port and port.ofport != -1):
                    self.port_dead(port)
        return skipped_devices

    def _write_endpoint_file(self, port_id, mapping_dict):
        return self._write_file(port_id, mapping_dict, self.epg_mapping_file)

    def _delete_endpoint_file(self, port_id):
        return self._delete_file(port_id, self.epg_mapping_file)

    def _delete_endpoint_files(self, port_id):
        # Delete all files for this specific port_id
        directory = os.path.dirname(self.epg_mapping_file)
        # Remove all existing EPs mapping for port_id
        for f in os.listdir(directory):
            if f.endswith('.' + FILE_EXTENSION) and port_id in f:
                try:
                    os.remove(os.path.join(directory, f))
                except OSError as e:
                    LOG.exception(e)

    def _write_vrf_file(self, vrf_id, mapping_dict):
        return self._write_file(vrf_id, mapping_dict, self.vrf_mapping_file)

    def _delete_vrf_file(self, vrf_id):
        return self._delete_file(vrf_id, self.vrf_mapping_file)

    def _write_file(self, port_id, mapping_dict, file_format):
        filename = file_format % port_id
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'w') as f:
            jsonutils.dump(mapping_dict, f, indent=4)

    def _delete_file(self, port_id, file_format):
        try:
            os.remove(file_format % port_id)
        except OSError as e:
            LOG.debug(e.message)

    def _fill_ip_mapping_info(self, port_id, port_mac, gbp_details,
                              ips, mapping):
        fip_fixed_ips = {}
        for fip in gbp_details.get('floating_ip', []):
            fm = {'uuid': fip['id'],
                  'mapped-ip': fip['fixed_ip_address'],
                  'floating-ip': fip['floating_ip_address']}
            if 'nat_epg_tenant' in fip:
                fm['policy-space-name'] = fip['nat_epg_tenant']
            if 'nat_epg_name' in fip:
                nat_epg = (
                    fip.get('nat_epg_app_profile',
                            gbp_details['app_profile_name']) + "|" +
                    fip['nat_epg_name'])
                fm['endpoint-group-name'] = nat_epg
                fip_fixed_ips.setdefault(nat_epg, set()).add(
                    fip['fixed_ip_address'])
            mapping.setdefault('ip-address-mapping', []).append(fm)

        es_using_int_fip = {4: set(), 6: set()}
        for ipm in gbp_details.get('ip_mapping', []):
            if (not ips or not ipm.get('external_segment_name') or
                not ipm.get('nat_epg_tenant') or
                not ipm.get('nat_epg_name')):
                continue
            es = ipm['external_segment_name']
            epg = (ipm.get('nat_epg_app_profile',
                           gbp_details['app_profile_name']) + "|" +
                   ipm['nat_epg_name'])
            ipm['nat_epg_name'] = epg
            next_hop_if, next_hop_mac = self._get_next_hop_info_for_es(ipm)
            if not next_hop_if or not next_hop_mac:
                continue
            fip_alloc_es = {
                4: self._get_int_fips(4, port_id, port_mac).get(es, {}),
                6: self._get_int_fips(6, port_id, port_mac).get(es, {})}
            for ip in ips:
                if ip in fip_fixed_ips.get(epg, []):
                    continue
                ip_ver = netaddr.IPAddress(ip).version
                fip = (fip_alloc_es[ip_ver].get(ip) or
                       self._alloc_int_fip(ip_ver, port_id, port_mac, es, ip))
                es_using_int_fip[ip_ver].add(es)
                ip_map = {'uuid': uuidutils.generate_uuid(),
                          'mapped-ip': ip,
                          'floating-ip': str(fip),
                          'policy-space-name': ipm['nat_epg_tenant'],
                          'endpoint-group-name': epg,
                          'next-hop-if': next_hop_if,
                          'next-hop-mac': next_hop_mac}
                mapping.setdefault('ip-address-mapping', []).append(ip_map)
        old_es = self._get_es_for_port(port_id, port_mac)
        new_es = es_using_int_fip[4] | es_using_int_fip[6]
        self._associate_port_with_es(port_id, port_mac, new_es)
        self._dissociate_port_from_es(port_id, port_mac, old_es - new_es)

        for ip_ver in es_using_int_fip.keys():
            fip_alloc = self._get_int_fips(ip_ver, port_id, port_mac)
            for es in fip_alloc.keys():
                if es not in es_using_int_fip[ip_ver]:
                    self._release_int_fip(ip_ver, port_id, port_mac, es)
                else:
                    for old in (set(fip_alloc[es].keys()) - set(ips)):
                        self._release_int_fip(ip_ver, port_id, port_mac, es,
                                              old)
        if 'ip-address-mapping' in mapping:
            mapping['ip-address-mapping'].sort(
                key=lambda x: (x['mapped-ip'], x['floating-ip']))

    def _get_int_fips(self, ip_ver, port_id, port_mac):
        return self.int_fip_alloc[ip_ver].get((port_id, port_mac), {})

    def _get_es_for_port(self, port_id, port_mac):
        """ Return ESs for which there is a internal FIP allocated """
        es = set(self._get_int_fips(4, port_id, port_mac).keys())
        es.update(self._get_int_fips(6, port_id, port_mac).keys())
        return es

    def _alloc_int_fip(self, ip_ver, port_id, port_mac, es, ip):
        fip = self.int_fip_pool[ip_ver].__iter__().next()
        self.int_fip_pool[ip_ver].remove(fip)
        self.int_fip_alloc[ip_ver].setdefault(
            (port_id, port_mac), {}).setdefault(es, {})[ip] = fip
        LOG.debug(_("Allocated internal v%(version)d FIP %(fip)s to "
                    "port %(port)s, %(mac)s, fixed IP %(ip)s "
                    "in external segment %(es)s"),
                  {'fip': fip, 'port': port_id, 'mac': port_mac,
                   'es': es, 'ip': ip, 'version': ip_ver})
        return fip

    def _release_int_fip(self, ip_ver, port_id, port_mac=None, es=None,
                         ip=None):
        if ip and es and port_mac:
            fips = self.int_fip_alloc[ip_ver].get(
                (port_id, port_mac), {}).get(es, {}).pop(ip, None)
            fips = (fips and [fips] or [])
        elif es and port_mac:
            fips = self.int_fip_alloc[ip_ver].get(
                (port_id, port_mac), {}).pop(es, {}).values()
        else:
            if port_mac:
                fip_map_list = self.int_fip_alloc[ip_ver].pop(
                    (port_id, port_mac), {}).values()
            else:
                fip_map_list = []
                for id_mac in self.int_fip_alloc[ip_ver].keys():
                    if id_mac[0] == port_id:
                        fip_map_list.extend(
                            self.int_fip_alloc[ip_ver].pop(
                                id_mac, {}).values())
            fips = []
            for x in fip_map_list:
                fips.extend(x.values())
        for float_ip in fips:
            self.int_fip_pool[ip_ver].add(float_ip)
        LOG.debug(_("Released internal v%(version)d FIP(s) %(fip)s "
                    "for port %(port)s, mac %(mac)s, "
                    "fixed IP %(ip)s, external segment %(es)s"),
                  {'fip': fips, 'port': port_id, 'mac': port_mac or '<all>',
                   'es': es or '<all>', 'ip': ip or '<all>',
                   'version': ip_ver})

    def _get_next_hop_info_for_es(self, ipm):
        es_name = ipm['external_segment_name']
        nh = self.ext_seg_next_hop.get(es_name)
        if not nh or not nh.is_valid():
            return (None, None)
        # create ep file for endpoint and snat tables
        if not nh.next_hop_iface:
            try:
                (nh.next_hop_iface, nh.next_hop_mac) = (
                    self.snat_iptables.setup_snat_for_es(es_name,
                        nh.ip_start, nh.ip_end, nh.ip_gateway,
                        nh.ip6_start, nh.ip6_end, nh.ip6_gateway,
                        nh.next_hop_mac))
                LOG.info(_("Created SNAT iptables for %(es)s: "
                           "iface %(if)s, mac %(mac)s"),
                         {'es': es_name, 'if': nh.next_hop_iface,
                          'mac': nh.next_hop_mac})
            except Exception as e:
                LOG.exception(_("Error while creating SNAT iptables for "
                                "%(es)s: %(ex)s"),
                              {'es': es_name, 'ex': e})
            self._create_host_endpoint_file(ipm, nh)
        return (nh.next_hop_iface, nh.next_hop_mac)

    def _create_host_endpoint_file(self, ipm, nh):
        ips = []
        for s, e in [(nh.ip_start, nh.ip_end), (nh.ip6_start, nh.ip6_end)]:
            if s:
                ips.extend(list(netaddr.iter_iprange(s, e or s)))
        ep_dict = {
            "attributes": {
                "vm-name": (
                    "snat|" +
                    cfg.CONF.host + "|" +
                    ipm["nat_epg_tenant"] + "|" +
                    ipm["nat_epg_name"]
                )
            },
            "policy-space-name": ipm['nat_epg_tenant'],
            "endpoint-group-name": ipm['nat_epg_name'],
            "interface-name": nh.next_hop_iface,
            "ip": [str(x) for x in ips],
            "mac": nh.next_hop_mac,
            "uuid": nh.uuid,
            "promiscuous-mode": True,
        }
        self._write_endpoint_file(nh.es_name, ep_dict)

    def _associate_port_with_es(self, port_id, port_mac, ess):
        for es in ess:
            self.es_port_dict.setdefault(es, set()).add((port_id, port_mac))

    def _dissociate_port_from_es(self, port_id, port_mac=None, ess=None):
        if ess is None:
            es_list = self.es_port_dict.keys()
        else:
            es_list = ess
        for es in es_list:
            if es not in self.es_port_dict:
                continue
            if port_mac:
                self.es_port_dict[es].discard((port_id, port_mac))
            else:
                entries = set([x for x in self.es_port_dict[es]
                               if x[0] == port_id])
                self.es_port_dict[es] -= entries
            if self.es_port_dict[es]:
                continue
            self.es_port_dict.pop(es)
            if es in self.ext_seg_next_hop:
                self.ext_seg_next_hop[es].next_hop_iface = None
                self.ext_seg_next_hop[es].next_hop_mac = None
            self._delete_endpoint_file(es)
            try:
                self.snat_iptables.cleanup_snat_for_es(es)
                LOG.debug("Removed SNAT iptables for %s", es)
            except Exception as e:
                LOG.warn(_("Failed to remove SNAT iptables for "
                           "%(es)s: %(ex)s"),
                         {'es': es, 'ex': e})

    def _load_es_next_hop_info(self, es_cfg):
        def parse_range(val):
            if val and val[0]:
                ip = [x.strip() for x in val[0].split(',', 1)]
                return (ip[0] or None,
                        (len(ip) > 1 and ip[1]) and ip[1] or None)
            return (None, None)

        def parse_gateway(val):
            return (val and '/' in val[0]) and val[0] or None

        self.ext_seg_next_hop = {}
        for es_name, es_info in es_cfg.iteritems():
            nh = ExtSegNextHopInfo(es_name)
            nh.from_config = True
            for key, value in es_info:
                if key == 'ip_address_range':
                    (nh.ip_start, nh.ip_end) = parse_range(value)
                elif key == 'ip_gateway':
                    nh.ip_gateway = parse_gateway(value)
                elif key == 'ip6_address_range':
                    (nh.ip6_start, nh.ip6_end) = parse_range(value)
                elif key == 'ip6_gateway':
                    nh.ip6_gateway = parse_gateway(value)
            self.ext_seg_next_hop[es_name] = nh
            LOG.debug(_("Found external segment: %s") % nh)

    def _handle_host_snat_ip(self, host_snat_ips):
        for hsi in host_snat_ips:
            LOG.debug(_("Auto-allocated host SNAT IP: %s"), hsi)
            es = hsi.get('external_segment_name')
            if not es:
                continue
            nh = self.ext_seg_next_hop.setdefault(es, ExtSegNextHopInfo(es))
            if nh.from_config:
                continue    # ignore auto-allocation if manually set
            ip = hsi.get('host_snat_ip')
            gw = ("%s/%s" % (hsi['gateway_ip'], hsi['prefixlen'])
                if (hsi.get('gateway_ip') and hsi.get('prefixlen')) else None)
            updated = False
            if netaddr.valid_ipv4(ip):
                if ip != nh.ip_start or gw != nh.ip_gateway:
                    nh.ip_start = ip
                    nh.ip_gateway = gw
                    updated = True
            elif netaddr.valid_ipv6(ip):
                if ip != nh.ip6_start or gw != nh.ip6_gateway:
                    nh.ip6_start = ip
                    nh.ip6_gateway = gw
                    updated = True
            else:
                LOG.info(_("Ignoring invalid auto-allocated SNAT IP %s"), ip)
            if updated:
                # Clear the interface so that SNAT iptables will be
                # re-created as required; leave MAC as is so that it will
                # be re-used
                nh.next_hop_iface = None
                LOG.info(_("Add/update SNAT info: %s"), nh)


def create_agent_config_map(conf):
    agent_config = ovs.create_agent_config_map(conf)
    agent_config['hybrid_mode'] = conf.OPFLEX.hybrid_mode
    agent_config['epg_mapping_dir'] = conf.OPFLEX.epg_mapping_dir
    agent_config['opflex_networks'] = conf.OPFLEX.opflex_networks
    agent_config['internal_floating_ip_pool'] = (
        conf.OPFLEX.internal_floating_ip_pool)
    agent_config['internal_floating_ip6_pool'] = (
        conf.OPFLEX.internal_floating_ip6_pool)
    # DVR not supported
    agent_config['enable_distributed_routing'] = False
    # ARP responder not supported
    agent_config['arp_responder'] = False

    # read external-segment next-hop info
    es_info = {}
    multi_parser = cfg.MultiConfigParser()
    multi_parser.read(conf.config_file)
    for parsed_file in multi_parser.parsed:
        for parsed_item in parsed_file.keys():
            if parsed_item.startswith('opflex_external_segment:'):
                es_name = parsed_item.split(':', 1)[1]
                if es_name:
                    es_info[es_name] = parsed_file[parsed_item].items()
    agent_config['external_segment'] = es_info
    agent_config['dhcp_domain'] = conf.dhcp_domain
    return agent_config


def main():
    cfg.CONF.register_opts(ip_lib.OPTS)
    cfg.CONF.register_opts(dhcp_config.DHCP_OPTS)
    config.register_root_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    q_utils.log_opt_values(LOG)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_('%s Agent terminated!'), e)
        sys.exit(1)

    is_xen_compute_host = 'rootwrap-xen-dom0' in cfg.CONF.AGENT.root_helper
    if is_xen_compute_host:
        # Force ip_lib to always use the root helper to ensure that ip
        # commands target xen dom0 rather than domU.
        cfg.CONF.set_default('ip_lib_force_root', True)
    try:
        agent = GBPOvsAgent(root_helper=cfg.CONF.AGENT.root_helper,
                            **agent_config)
    except RuntimeError as e:
        LOG.error(_("%s Agent terminated!"), e)
        sys.exit(1)
    signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_("Initializing metadata service ... "))
    helper = cfg.CONF.AGENT.root_helper
    metadata_mgr = as_metadata_manager.AsMetadataManager(LOG, helper)
    metadata_mgr.ensure_initialized()

    LOG.info(_("Agent initialized successfully, now running... "))
    agent.daemon_loop()


if __name__ == "__main__":
    main()
