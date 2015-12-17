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

from neutron.common import constants as n_constants
from neutron.i18n import _LI
from neutron.openstack.common import uuidutils
from oslo_log import log as logging
from oslo_serialization import jsonutils

from opflexagent import constants as ofcst
from opflexagent import snat_iptables_manager
from opflexagent.utils.ep_managers import endpoint_manager_base

LOG = logging.getLogger(__name__)

FILE_EXTENSION = "ep"
FILE_NAME_FORMAT = "%s." + FILE_EXTENSION
VRF_FILE_EXTENSION = "rdconfig"
VRF_FILE_NAME_FORMAT = "%s." + VRF_FILE_EXTENSION


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


class EndpointFileManager(endpoint_manager_base.EndpointManagerBase):
    """ File Based endpoint manager

    File based interface between the GBP Opflex agent and the opflex OVS
    agent.
    """

    def initialize(self, host, bridge_manager, config):
        LOG.info(_LI("Initializing the Endpoint File Manager. \n %s"), config)
        separator = (config['epg_mapping_dir'][-1] if
                     config['epg_mapping_dir'] else '')
        self.epg_mapping_file = (config['epg_mapping_dir'] +
                                 ('/' if separator != '/' else '') +
                                 FILE_NAME_FORMAT)
        self.vrf_mapping_file = (config['epg_mapping_dir'] +
                                 ('/' if separator != '/' else '') +
                                 VRF_FILE_NAME_FORMAT)
        self.file_formats = [self.epg_mapping_file, self.vrf_mapping_file]
        self.dhcp_domain = config['dhcp_domain']
        self.es_port_dict = {}
        self.vrf_dict = {}
        self.vif_to_vrf = {}
        self._load_es_next_hop_info(config['external_segment'])
        self.int_fip_alloc = {4: {}, 6: {}}
        self.int_fip_pool = {
            4: netaddr.IPSet(config['internal_floating_ip_pool']),
            6: netaddr.IPSet(config['internal_floating_ip6_pool'])}
        if ofcst.METADATA_DEFAULT_IP in self.int_fip_pool[4]:
            self.int_fip_pool[4].remove(ofcst.METADATA_DEFAULT_IP)

        self._setup_ep_directory()
        self.snat_iptables = snat_iptables_manager.SnatIptablesManager(
            bridge_manager.int_br)
        self.host = host
        return self

    def declare_endpoint(self, port, mapping):
        LOG.info(_LI("Endpoint declaration requested for port %s"),
                 port.vif_id)
        LOG.debug("Mapping file for port %(port)s, %(mapping)s" %
                  {'port': port.vif_id, 'mapping': mapping})

        if not mapping:
            return
        else:
            # PT cleanup is needed before writing the new endpoint files
            # TODO(ivar): only cleanup what's not needed.
            self._mapping_cleanup(port.vif_id, cleanup_vrf=False)

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
            for fixed in (mapping.get('fixed_ips') or port.fixed_ips):
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
            LOG.debug("Main file mapping %s", mapping_copy)
            self._mapping_to_file(port, mapping_copy, port.fixed_ips)
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
                LOG.debug("Secondary file mapping %s", mapping_copy)
                self._mapping_to_file(port, mapping_copy, [])

    def undeclare_endpoint(self, port_id):
        LOG.info(_LI("Endpoint undeclare requested for port %s"), port_id)
        self._mapping_cleanup(port_id)

    # Private Methods

    def _setup_ep_directory(self):
        """ Setup endpoint directory

        The EP directory gets created if needed, and all the stale EP files
        removed
        """
        created = False
        for file_format in self.file_formats:
            directory = os.path.dirname(file_format)
            if not os.path.exists(directory):
                created = True
                os.makedirs(directory)
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

    def _mapping_cleanup(self, vif_id, cleanup_vrf=True):
        LOG.debug('Cleaning mapping for vif id %s', vif_id)
        self._delete_endpoint_files(vif_id)
        if cleanup_vrf:
            es = self._get_es_for_port(vif_id)
            self._dissociate_port_from_es(vif_id, es)
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

    def _mapping_to_file(self, port, mapping, fixed_ips):
        """Mapping to file.

        Converts the port mapping into file.
        """
        # Skip router-interface ports - they interfere with OVS pipeline

        fixed_ips = mapping.get('fixed_ips') or fixed_ips
        # Routing is handled by ACI
        if port.device_owner in [n_constants.DEVICE_OWNER_ROUTER_INTF]:
            return
        ips_ext = mapping.get('extra_ips') or []
        mac = mapping.get('mac_address') or port.vif_mac
        mapping_dict = {
            "policy-space-name": mapping['ptg_tenant'],
            "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                    mapping['endpoint_group_name']),
            "interface-name": port.port_name,
            "promiscuous-mode": mapping.get('promiscuous_mode') or False,
            "uuid": '%s|%s' % (port.vif_id, mac.replace(':', '-')),
            'neutron-network': port.net_uuid}

        ips = [x['ip_address'] for x in fixed_ips]

        virtual_ips = []
        if port.device_owner == n_constants.DEVICE_OWNER_DHCP:
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
        self._fill_ip_mapping_info(port.vif_id, mapping, ips + ips_ext,
                                   mapping_dict)
        # Create one file per MAC address.
        LOG.debug("Final endpoint file for port %(port)s: \n %(mapping)s" %
                  {'port': port.vif_id, 'mapping': mapping_dict})
        self._write_endpoint_file(port.vif_id + '_' + mac, mapping_dict)
        self.vrf_info_to_file(mapping, vif_id=port.vif_id)

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

    def _map_dhcp_info(self, fixed_ips, subnets, mapping_dict):
        """ Add DHCP specific info to the EP file."""
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

    def _fill_ip_mapping_info(self, port_id, gbp_details, ips, mapping):
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
            fip_alloc_es = {4: self._get_int_fips(4, port_id).get(es, {}),
                            6: self._get_int_fips(6, port_id).get(es, {})}
            for ip in ips:
                if ip in fip_fixed_ips.get(epg, []):
                    continue
                ip_ver = netaddr.IPAddress(ip).version
                fip = (fip_alloc_es[ip_ver].get(ip) or
                       self._alloc_int_fip(ip_ver, port_id, es, ip))
                es_using_int_fip[ip_ver].add(es)
                ip_map = {'uuid': uuidutils.generate_uuid(),
                          'mapped-ip': ip,
                          'floating-ip': str(fip),
                          'policy-space-name': ipm['nat_epg_tenant'],
                          'endpoint-group-name': epg,
                          'next-hop-if': next_hop_if,
                          'next-hop-mac': next_hop_mac}
                mapping.setdefault('ip-address-mapping', []).append(ip_map)
        old_es = self._get_es_for_port(port_id)
        new_es = es_using_int_fip[4] | es_using_int_fip[6]
        self._associate_port_with_es(port_id, new_es)
        self._dissociate_port_from_es(port_id, old_es - new_es)

        for ip_ver in es_using_int_fip.keys():
            fip_alloc = self._get_int_fips(ip_ver, port_id)
            for es in fip_alloc.keys():
                if es not in es_using_int_fip[ip_ver]:
                    self._release_int_fip(ip_ver, port_id, es)
                else:
                    for old in (set(fip_alloc[es].keys()) - set(ips)):
                        self._release_int_fip(ip_ver, port_id, es, old)
        if 'ip-address-mapping' in mapping:
            mapping['ip-address-mapping'].sort(
                key=lambda x: (x['mapped-ip'], x['floating-ip']))

    def _get_int_fips(self, ip_ver, port_id):
        return self.int_fip_alloc[ip_ver].get(port_id, {})

    def _get_es_for_port(self, port_id):
        """ Return ESs for which there is a internal FIP allocated """
        es = set(self._get_int_fips(4, port_id).keys())
        es.update(self._get_int_fips(6, port_id).keys())
        return es

    def _alloc_int_fip(self, ip_ver, port_id, es, ip):
        fip = self.int_fip_pool[ip_ver].__iter__().next()
        self.int_fip_pool[ip_ver].remove(fip)
        self.int_fip_alloc[ip_ver].setdefault(
            port_id, {}).setdefault(es, {})[ip] = fip
        LOG.debug(_("Allocated internal FIP %(fip)s to port %(port)s, "
                    "fixed IP %(ip)s in external segment %(es)s"),
                  {'fip': fip, 'port': port_id, 'es': es, 'ip': ip})
        return fip

    def _release_int_fip(self, ip_ver, port_id, es=None, ip=None):
        if es and ip:
            fips = self.int_fip_alloc[ip_ver].get(port_id, {}).get(
                es, {}).pop(ip, None)
            fips = (fips and [fips] or [])
        elif es:
            fips = self.int_fip_alloc[ip_ver].get(port_id, {}).pop(
                es, {}).values()
        else:
            fip_alloc = self.int_fip_alloc[ip_ver].pop(port_id, {}).values()
            fips = []
            for x in fip_alloc:
                fips.extend(x.values())
        for ip in fips:
            self.int_fip_pool[ip_ver].add(ip)
        LOG.debug(_("Released internal FIP(s) %(fip)s for port %(port)s, "
                    "fixed IP %(ip)s, external segment %(es)s"),
                  {'fip': fips, 'port': port_id,
                   'es': es or '<all>', 'ip': ip or '<all>'})

    def _associate_port_with_es(self, port_id, ess):
        for es in ess:
            self.es_port_dict.setdefault(es, set()).add(port_id)

    def _dissociate_port_from_es(self, port_id, ess):
        for es in ess:
            if es not in self.es_port_dict:
                continue
            self.es_port_dict[es].discard(port_id)
            if self.es_port_dict[es]:
                continue
            self.es_port_dict.pop(es)
            if es in self.ext_seg_next_hop:
                self.ext_seg_next_hop[es].next_hop_iface = None
                self.ext_seg_next_hop[es].next_hop_mac = None
            self._delete_endpoint_file(es)
            try:
                self.snat_iptables.cleanup_snat_for_es(es)
            except Exception as e:
                LOG.warn(_("Failed to remove SNAT iptables for "
                           "%(es)s: %(ex)s"),
                         {'es': es, 'ex': e})

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
                    vrf_info_copy['internal-subnets']) +
                    [ofcst.METADATA_SUBNET])
                self._write_vrf_file(mapping['l3_policy_id'], vrf_info_copy)
                curr_vrf['info'] = vrf_info
            if vif_id:
                curr_vrf['vifs'].add(vif_id)
                self.vif_to_vrf[vif_id] = mapping['l3_policy_id']

    def _create_host_endpoint_file(self, ipm, nh):
        ips = []
        for s, e in [(nh.ip_start, nh.ip_end), (nh.ip6_start, nh.ip6_end)]:
            if s:
                ips.extend(list(netaddr.iter_iprange(s, e or s)))
        ep_dict = {
            "attributes": {
                "vm-name": (
                    "snat|" +
                    self.host + "|" + ipm["nat_epg_tenant"] + "|" +
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