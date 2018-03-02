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

import importlib
import signal
import sys
import time

from neutron.agent.common import polling
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_firewall
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import eventlet_utils
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron.conf.agent import common as config
from neutron.conf.agent import dhcp as dhcp_config
from neutron.plugins.ml2.drivers.openvswitch.agent import (
    ovs_neutron_agent as ovs)
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron_lib import constants as n_constants
from neutron_lib import context
from neutron_lib import exceptions
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import excutils

from opflexagent import as_metadata_manager
from opflexagent import config as ofcfg  # noqa
from opflexagent import constants as ofcst
from opflexagent import opflex_notify
from opflexagent import rpc
from opflexagent.utils.bridge_managers import ovs_manager
from opflexagent.utils.ep_managers import endpoint_file_manager as ep_manager
from opflexagent.utils.port_managers import async_port_manager as port_manager

eventlet_utils.monkey_patch()
LOG = logging.getLogger(__name__)

DVS_AGENT_MODULE = 'vmware_dvs.agent.dvs_neutron_agent'


# TODO(bose) Remove when we switch to using RPC method
# get_devices_details_list_and_failed_devices
class DeviceListRetrievalError(exceptions.NeutronException):
    message = _("Unable to retrieve port details for devices: %(devices)s ")


class GBPOpflexAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                     rpc.OpenstackRpcMixin):
    """Group Based Policy Opflex Agent.

    The GBP opflex agent assumes a pre-existing bridge (integration bridge is
    not required). This agent is an interface between Openstack Neutron and
    agent-ovs, which renders policies from an OpFlex-based SDN controller
    (like Cisco ACI) into OpenFlow rules for OVS.

    The GBP Opflex Agent
    """

    def __init__(self, root_helper=None, *args, **kwargs):
        self.opflex_networks = kwargs['opflex_networks']
        if self.opflex_networks and self.opflex_networks[0] == '*':
            self.opflex_networks = None
        self.root_helper = root_helper
        self.notify_worker = opflex_notify.worker()
        self.host = cfg.CONF.host
        agent_conf = cfg.CONF.AGENT
        ovs_conf = cfg.CONF.OVS
        opflex_conf = cfg.CONF.OPFLEX

        try:
            bridge_mappings = helpers.parse_mappings(ovs_conf.bridge_mappings)
        except ValueError as e:
            raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

        self.agent_state = {
            'binary': 'neutron-opflex-agent',
            'host': self.host,
            'topic': n_constants.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': bridge_mappings,
                               'opflex_networks': self.opflex_networks},
            'agent_type': ofcst.AGENT_TYPE_OPFLEX_OVS,
            'start_flag': True}

        # Initialize OVS Manager
        self.bridge_manager = ovs_manager.OvsManager().initialize(
            self.host, ovs_conf, opflex_conf)
        # Stores port update notifications for processing in main rpc loop
        self.updated_ports = set()
        # Stores port delete notifications
        self.deleted_ports = set()
        # Stores VRF update notifications
        self.updated_vrf = set()
        self.setup_rpc()
        self.local_ip = ovs_conf.local_ip
        self.polling_interval = agent_conf.polling_interval
        self.config_apply_interval = kwargs['config_apply_interval']
        self.minimize_polling = agent_conf.minimize_polling
        self.ovsdb_monitor_respawn_interval = (
            agent_conf.ovsdb_monitor_respawn_interval or
            constants.DEFAULT_OVSDBMON_RESPAWN)
        self.setup_report()
        self.supported_pt_network_types = [ofcst.TYPE_OPFLEX]

        # Initialize iteration counter
        self.iter_num = 0
        self.run_daemon_loop = True
        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()

        self.quitting_rpc_timeout = agent_conf.quitting_rpc_timeout
        # Initialize the Endpoint Manager.
        # TODO(ivar): make these components pluggable.
        self.ep_manager = ep_manager.EndpointFileManager().initialize(
            self.host, self.bridge_manager, kwargs)
        self.port_manager = port_manager.AsyncPortManager().initialize(
            self.host, self, kwargs)

    def setup_report(self):
        report_interval = cfg.CONF.AGENT.report_interval
        # Be synchronous for the first report
        self.use_call = True
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def _report_state(self):
        # How many devices are likely used by a VM
        self.agent_state.get('configurations')['devices'] = (
            self.bridge_manager.int_br_device_count)

        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state,
                                        self.use_call)
            self.use_call = False
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception("Failed reporting state!")

    def setup_rpc(self):
        self.agent_id = 'opflex-agent-%s' % cfg.CONF.host
        self.context = context.get_admin_context_without_session()
        # Set GBP rpc API
        self.of_rpc = rpc.GBPServerRpcApi(rpc.TOPIC_OPFLEX)
        self.plugin_rpc = ovs.OVSPluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.sg_agent = sg_rpc.SecurityGroupAgentRpc(
            self.context, self.sg_plugin_rpc, defer_refresh_firewall=True)

        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.topic = topics.AGENT
        self.endpoints = [self]
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.PORT, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [topics.SUBNET, topics.UPDATE],
                     [rpc.TOPIC_OPFLEX, rpc.VRF, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(
            self.endpoints, self.topic, consumers, start_listening=False)

    def _agent_has_updates(self, polling_manager):
        return (polling_manager.is_polling_required or
                self.updated_ports or
                self.deleted_ports or
                self.updated_vrf or
                self.sg_agent.firewall_refresh_needed())

    def _info_has_changes(self, port_info):
        return (port_info.get('added') or
                port_info.get('removed') or
                port_info.get('updated') or
                port_info.get('vrf_updated'))

    def try_port_binding(self, port, net_uuid, network_type, physical_network,
                         fixed_ips, device_owner):
        port.net_uuid = net_uuid
        port.device_owner = device_owner
        port.fixed_ips = fixed_ips
        if not port.gbp_details:
            # Mapping is empty, this port left the Opflex policy space.
            LOG.warn("Mapping for port %s is None, undeclaring the Endpoint",
                     port.vif_id)
            self.port_unbound(port.vif_id)
        elif network_type in self.supported_pt_network_types:
            if ((self.opflex_networks is None) or
                    (physical_network in self.opflex_networks)):
                # Endpoint Manager to process the EP info
                LOG.debug("Processing the endpoint mapping "
                          "for port %(port)s: \n mapping: %(mapping)s" % {
                              'port': port.vif_id,
                              'mapping': port.gbp_details})
                self.port_bound(port)
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

    def port_bound(self, port):
        self.bridge_manager.add_patch_ports([port.vif_id])
        self.ep_manager.declare_endpoint(port, port.gbp_details)
        self.bridge_manager.manage_trunk(port)

    def port_unbound(self, vif_id):
        """Unbind port."""
        self.ep_manager.undeclare_endpoint(vif_id)
        self.bridge_manager.delete_patch_ports([vif_id])
        self.bridge_manager.unmanage_trunk(vif_id)

    def process_network_ports(self, port_info, ovs_restarted):
        resync_a = False
        resync_b = False
        self.sg_agent.setup_port_filters(port_info.get('added', set()),
                                         port_info.get('updated', set()))
        # VIF wiring needs to be performed always for 'new' devices.
        # For updated ports, re-wiring is not needed in most cases, but needs
        # to be performed anyway when the admin state of a device is changed.
        # A device might be both in the 'added' and 'updated'
        # list at the same time; avoid processing it twice.
        devices_added_updated = (port_info.get('added', set()) |
                                 port_info.get('updated', set()))
        if devices_added_updated:
            start = time.time()
            try:
                # Schedule request for port update
                self.port_manager.schedule_update(devices_added_updated)
                # Apply configuration
                skipped_devices = self.port_manager.apply_config()
                LOG.debug("process_network_ports - iteration:%(iter_num)d - "
                          "treat_devices_added_or_updated completed. "
                          "Skipped %(num_skipped)d devices of "
                          "%(num_current)d devices currently available. "
                          "Time elapsed: %(elapsed).3f",
                          {'iter_num': self.iter_num,
                           'num_skipped': len(skipped_devices),
                           'num_current': len(port_info['current']),
                           'elapsed': time.time() - start})
                # Update the list of current ports storing only those which
                # have been actually processed.
                port_info['current'] = (port_info['current'] -
                                        set(skipped_devices))
            except DeviceListRetrievalError:
                # Need to resync as there was an error with server
                # communication.
                LOG.exception("process_network_ports - iteration:%d - "
                              "failure while retrieving port details "
                              "from server", self.iter_num)
                resync_a = True
        if 'removed' in port_info:
            start = time.time()
            resync_b = self.treat_devices_removed(port_info['removed'])
            LOG.debug("process_network_ports - iteration:%(iter_num)d - "
                      "treat_devices_removed completed in %(elapsed).3f",
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        if port_info.get('vrf_updated'):
            self.process_vrf_update(port_info['vrf_updated'])
        # If one of the above operations fails => resync with plugin
        return resync_a | resync_b

    def treat_devices_removed(self, devices):
        resync = False
        self.port_manager.unschedule_update(devices)
        self.sg_agent.remove_devices_filter(devices)
        for device in devices:
            LOG.info("Attachment %s removed", device)
            try:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   cfg.CONF.host)
            except Exception as e:
                LOG.debug("port_removed failed for %(device)s: %(e)s",
                          {'device': device, 'e': e})
                resync = True
                continue
            self.port_unbound(device)
        return resync

    def process_vrf_update(self, vrf_update):
        # TODO(ivar): use the async model
        vrf_details_list = self.of_rpc.get_vrf_details_list(
            self.context, self.agent_id, vrf_update, self.host)
        for details in vrf_details_list:
            # REVISIT(ivar): this is not a public facing API, we will move to
            # the right method once the redesign is complete.
            self.ep_manager.vrf_info_to_file(details)

    # NOTE(ivar): This method doesn't belong here or anywhere near the Neutron
    # agent at all: Nova's compute agent creates the hybrid bridge and should
    # configure it properly. However, because of support/issues/591 we need
    # to make sure that LB aeging is set to 0.
    def _set_hybrid_bridge_aeging_to_zero(self, device):
        # Only execute if IPTables firewall driver is used
        if isinstance(self.sg_agent.firewall,
                      iptables_firewall.IptablesFirewallDriver):
            # From nova.network.model.py
            NIC_NAME_LEN = 14
            # Naming convention from nova.virt.libvirt/vif.py
            br_name = ("qbr" + device)[:NIC_NAME_LEN]
            cmd = ['brctl', 'setageing', br_name, '0']
            try:
                self.sg_agent.firewall.iptables.execute(cmd, run_as_root=True)
            except RuntimeError as e:
                with excutils.save_and_reraise_exception() as ctx:
                    if 'No such device' in e.message:
                        # No need to rerise, port could be bound somehow else
                        ctx.reraise = False
                        LOG.warn("Device %s not found while disabling mac "
                                 "learning" % br_name)

    def treat_devices_added_or_updated(self, details):
        """Process added or updated devices
        :param: Port details retrieved from the Neutron server
        :returns: Boolean indicating whether the device was processed or
                  skipped
        """
        device = details['device']
        LOG.debug("Processing port: %s", device)
        # REVISIT(ivar): this is not a public facing API, we will move to
        # the right method once the redesign is complete.
        port = self.bridge_manager.int_br.get_vif_port_by_id(device)
        if port:
            # If the following command fails (RuntimeException) the binding
            # fails.
            self._set_hybrid_bridge_aeging_to_zero(device)
            gbp_details = details.get('gbp_details')
            trunk_details = details.get('trunk_details')
            neutron_details = details.get('neutron_details')
            if gbp_details and 'port_id' not in gbp_details:
                # The port is dead
                details.pop('port_id', None)
            if (gbp_details and gbp_details.get('host') and
                gbp_details['host'] != self.host):
                    self.port_unbound(device)
                    return False
            elif neutron_details and 'port_id' in neutron_details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                # Inject GBP/Trunk details
                port.gbp_details = gbp_details
                port.trunk_details = trunk_details
                self.treat_vif_port(port, neutron_details['port_id'],
                                    neutron_details['network_id'],
                                    neutron_details['network_type'],
                                    neutron_details['physical_network'],
                                    neutron_details['admin_state_up'],
                                    neutron_details['fixed_ips'],
                                    neutron_details['device_owner'])
                # update plugin about port status
                if neutron_details.get('admin_state_up'):
                    LOG.debug(_("Setting status for %s to UP"), device)
                    self.plugin_rpc.update_device_up(
                        self.context, device, self.agent_id, self.host)
                else:
                    LOG.debug(_("Setting status for %s to DOWN"), device)
                    self.plugin_rpc.update_device_down(
                        self.context, device, self.agent_id, self.host)
                LOG.info(_("Configuration for device %s completed."),
                         device)
            else:
                LOG.warn(_("Device %s not defined on plugin"), device)
                if port and port.ofport != -1:
                    self.port_unbound(port.vif_id)
                    return False
        else:
            # The port disappeared and cannot be processed
            LOG.info(_("Port %s was not found on the integration bridge "
                       "and will therefore not be processed"), device)
            self.port_unbound(device)
            return False
        return True

    def treat_vif_port(self, vif_port, port_id, network_id, network_type,
                       physical_network, admin_state_up,
                       fixed_ips, device_owner):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware
        if not vif_port.ofport:
            LOG.warn("VIF port: %s has no ofport configured, "
                     "and might not be able to transmit", vif_port.vif_id)
        if vif_port:
            if admin_state_up:
                self.try_port_binding(vif_port, network_id, network_type,
                                      physical_network, fixed_ips,
                                      device_owner)
            else:
                self.port_unbound(vif_port.vif_id)
        else:
            LOG.debug("No VIF port for port %s defined on agent.", port_id)

    def loop_count_and_wait(self, start_time, port_stats):
        # sleep till end of polling interval
        elapsed = time.time() - start_time
        LOG.debug("Agent rpc_loop - iteration:%(iter_num)d "
                  "completed. Processed ports statistics: "
                  "%(port_stats)s. Elapsed:%(elapsed).3f",
                  {'iter_num': self.iter_num,
                   'port_stats': port_stats,
                   'elapsed': elapsed})
        sleep = False
        while elapsed < self.polling_interval:
            self.port_manager.apply_config()
            # TODO(ivar): Verify optimal sleep time
            sleep = True
            time.sleep(min(self.config_apply_interval,
                           self.polling_interval - elapsed))
            elapsed = time.time() - start_time
        if not sleep:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
            # Still apply config at least once
            self.port_manager.apply_config()
        self.iter_num = self.iter_num + 1

    def rpc_loop(self, polling_manager):
        sync = True
        ports = set()
        ovs_restarted = False
        while self.run_daemon_loop:
            start = time.time()
            port_stats = {'regular': {'added': 0,
                                      'updated': 0,
                                      'removed': 0},
                          'ancillary': {'added': 0,
                                        'removed': 0}}
            LOG.debug("Agent rpc_loop - iteration:%d started",
                      self.iter_num)
            if sync:
                LOG.info("Agent out of sync with plugin!")
                ports.clear()
                sync = False
                polling_manager.force_polling()
            ovs_status = self.bridge_manager.check_bridge_status()
            if ovs_status == constants.OVS_RESTARTED:
                self.bridge_manager.setup_integration_bridge()
            elif ovs_status == constants.OVS_DEAD:
                # Agent doesn't apply any operations when ovs is dead, to
                # prevent unexpected failure or crash. Sleep and continue
                # loop in which ovs status will be checked periodically.
                self.loop_count_and_wait(start, port_stats)
                continue

            ovs_restarted |= (ovs_status == constants.OVS_RESTARTED)
            if self._agent_has_updates(polling_manager) or ovs_restarted:
                try:
                    ports, sync, ovs_restarted = self._main_loop(
                        ports, ovs_restarted, start, port_stats,
                        polling_manager, sync)
                except Exception:
                    LOG.exception("Error while processing VIF ports")
                    sync = True

            self.loop_count_and_wait(start, port_stats)

    def _main_loop(self, ports, ovs_restarted, start, port_stats,
                   polling_manager, sync):
        LOG.debug("Agent rpc_loop - iteration:%(iter_num)d - "
                  "starting polling. Elapsed:%(elapsed).3f",
                  {'iter_num': self.iter_num,
                   'elapsed': time.time() - start})
        # Save updated ports dict to perform rollback in
        # case resync would be needed, and then clear
        # self.updated_ports. As the greenthread should not yield
        # between these two statements, this will be thread-safe
        updated_ports_copy = self.updated_ports
        deleted_ports_copy = self.deleted_ports
        updated_vrf_copy = self.updated_vrf
        self.updated_vrf = set()
        self.deleted_ports = set()
        self.updated_ports = set()
        try:
            reg_ports = (set() if ovs_restarted else ports)
            port_info = self.bridge_manager.scan_ports(
                reg_ports, updated_ports_copy)
            removed_eps = (self.ep_manager.get_registered_endpoints() -
                           port_info['current'])
            port_info['removed'] = port_info.get(
                'removed', set()) | removed_eps | deleted_ports_copy

            vrf_info = updated_vrf_copy & set(self.ep_manager.vrf_dict.keys())
            port_info['vrf_updated'] = vrf_info
            LOG.debug("Agent rpc_loop - iteration:%(iter_num)d - "
                      "port information retrieved. "
                      "Elapsed:%(elapsed).3f",
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
            # Secure and wire/unwire VIFs and update their status
            # on Neutron server
            if (self._info_has_changes(port_info) or
                    self.sg_agent.firewall_refresh_needed() or
                    ovs_restarted):
                LOG.debug("Starting to process devices in:%s",
                          port_info)
                # If treat devices fails - must resync with plugin
                sync = self.process_network_ports(port_info, ovs_restarted)
                LOG.debug("Agent rpc_loop - iteration:%(iter_num)d - "
                          "ports processed. Elapsed:%(elapsed).3f",
                          {'iter_num': self.iter_num,
                           'elapsed': time.time() - start})
                port_stats['regular']['added'] = (
                    len(port_info.get('added', [])))
                port_stats['regular']['updated'] = (
                    len(port_info.get('updated', [])))
                port_stats['regular']['removed'] = (
                    len(port_info.get('removed', [])))
            ports = port_info['current']
            polling_manager.polling_completed()
            # Keep this flag in the last line of "try" block,
            # so we can sure that no other Exception occurred.
            if not sync:
                ovs_restarted = False
            return ports, sync, ovs_restarted
        except Exception:
            with excutils.save_and_reraise_exception():
                self.updated_ports |= updated_ports_copy
                self.deleted_ports |= deleted_ports_copy
                self.updated_vrf |= updated_vrf_copy

    def daemon_loop(self):
        with polling.get_polling_manager(
                self.minimize_polling,
                self.ovsdb_monitor_respawn_interval) as pm:
            self.rpc_loop(polling_manager=pm)

    def _handle_sigterm(self, signum, frame):
        LOG.debug("Agent caught SIGTERM, quitting daemon loop.")
        self.run_daemon_loop = False
        if self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)

    def set_rpc_timeout(self, timeout):
        for rpc_api in (self.plugin_rpc, self.sg_plugin_rpc, self.state_rpc):
            rpc_api.client.timeout = timeout


def create_agent_config_map(conf):
    agent_config = {}
    agent_config['epg_mapping_dir'] = conf.OPFLEX.epg_mapping_dir
    agent_config['opflex_networks'] = conf.OPFLEX.opflex_networks
    agent_config['endpoint_request_timeout'] = (
        conf.OPFLEX.endpoint_request_timeout)
    agent_config['config_apply_interval'] = conf.OPFLEX.config_apply_interval
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
    try:
        agent_config['dhcp_domain'] = conf.dhcp_domain
    except cfg.NoSuchOptError:
        agent_config['dhcp_domain'] = conf.dns_domain
    agent_config['nat_mtu_size'] = conf.OPFLEX.nat_mtu_size
    return agent_config


def main():
    cfg.CONF.register_opts(ip_lib.OPTS)
    dhcp_config.register_agent_dhcp_opts(cfg.CONF)
    cfg.CONF.set_override("ovsdb_interface", "vsctl", group="OVS")
    config.register_root_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    q_utils.log_opt_values(LOG)

    agent_mode = cfg.CONF.OPFLEX.agent_mode
    if agent_mode == 'dvs':
        agent = main_dvs()
    elif agent_mode == 'dvs_no_binding':
        agent = main_dvs(no_binding=True)
    else:
        agent = main_opflex()
    if not agent:
        sys.exit(1)

    LOG.info(_("Agent initialized successfully, now running... "))
    agent.daemon_loop()


def agent_startup_helper(create_config_map_fn, agent_class, root_helper=None):
    try:
        agent_config = create_config_map_fn(cfg.CONF)
    except ValueError as e:
        LOG.error(_("Couldn't create config map (%s), Agent terminated!"), e)
        return None

    try:
        if root_helper:
            agent = agent_class(root_helper, **agent_config)
        else:
            agent = agent_class(**agent_config)

    except RuntimeError as e:
        LOG.error(_("Couldn't create agent (%s), Agent terminated!"), e)
        return None
    signal.signal(signal.SIGTERM, agent._handle_sigterm)
    return agent


def main_dvs(no_binding=False):
    dvs_agent = None
    try:
        dvs_agent = importlib.import_module(DVS_AGENT_MODULE)
    except ValueError as e:
        LOG.error(
            "Couldn't import DVS agent class (%s), Agent terminated!", e)
        return None

    def dummy_function(config, pg_cache=False):
        return {}

    if no_binding:
        dvs_agent.dvs_util.create_network_map_from_config = dummy_function

    class DVSAgentNoBinding(dvs_agent.DVSAgent):

        # Specialize the RPCs to be No-Ops
        def create_network(self, context, current, segment):
            pass

        def delete_network(self, context, current, segment):
            pass

        def network_delete(self, context, network_id):
            pass

        def update_network(self, context, current, segment, original):
            pass

        def bind_port(self, context, current,
                      network_segments, network_current):
            pass

        def post_update_port(self, context, current, original, segment):
            pass

        def delete_port(self, context, current, original, segment):
            pass

    if no_binding:
        agent_class = DVSAgentNoBinding
    else:
        agent_class = dvs_agent.DVSAgent

    create_config_map_fn = dvs_agent.create_agent_config_map
    agent = agent_startup_helper(create_config_map_fn, agent_class)

    return agent


def main_opflex():
    agent_class = GBPOpflexAgent
    root_helper = cfg.CONF.AGENT.root_helper
    create_config_map_fn = create_agent_config_map
    agent = agent_startup_helper(create_config_map_fn, agent_class,
                         root_helper=root_helper)

    # Start everything.
    LOG.info(_("Initializing metadata service ... "))
    helper = cfg.CONF.AGENT.root_helper
    metadata_mgr = as_metadata_manager.AsMetadataManager(LOG, helper)
    metadata_mgr.ensure_initialized()
    return agent


if __name__ == "__main__":
    main()
