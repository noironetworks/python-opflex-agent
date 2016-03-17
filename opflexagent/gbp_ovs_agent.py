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

import signal
import sys
import time

from neutron.agent.common import config
from neutron.agent.common import polling
from neutron.agent.dhcp import config as dhcp_config
from neutron.agent.linux import ip_lib
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import constants as n_constants
from neutron.common import eventlet_utils
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron.i18n import _LE, _LI, _LW
from neutron import context
from neutron.openstack.common import loopingcall
from neutron.plugins.openvswitch.agent import ovs_neutron_agent as ovs
from neutron.plugins.openvswitch.common import constants
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from opflexagent import as_metadata_manager
from opflexagent import config as ofcfg  # noqa
from opflexagent import constants as ofcst
from opflexagent import opflex_notify
from opflexagent import rpc
from opflexagent.utils.bridge_managers import ovs_manager
from opflexagent.utils.ep_managers import endpoint_file_manager as ep_manager

eventlet_utils.monkey_patch()
LOG = logging.getLogger(__name__)


class GBPOvsPluginApi(rpc.GBPServerRpcApiMixin):
    pass


class GBPOpflexAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                     rpc.GbpNeutronAgentRpcCallbackMixin):
    """Group Based Policy Opflex Agent.

    The GBP opflex agent assumes a pre-existing bridge (integration bridge is
    not required). This agent is an interface between Openstack Neutron and
    agent-ovs, which renders policies from an OpFlex-based SDN controller
    (like Cisco ACI) into OpenFlow rules for OVS.

    The GBP Opflex Agent
    """

    target = oslo_messaging.Target(version='1.2')

    def __init__(self, root_helper=None, **kwargs):
        self.opflex_networks = kwargs['opflex_networks']
        if self.opflex_networks and self.opflex_networks[0] == '*':
            self.opflex_networks = None
        self.root_helper = root_helper
        self.notify_worker = opflex_notify.worker()
        self.host = cfg.CONF.host

        self.agent_state = {
            'binary': 'neutron-opflex-agent',
            'host': self.host,
            'topic': n_constants.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': kwargs['bridge_mappings'],
                               'opflex_networks': self.opflex_networks},
            'agent_type': ofcst.AGENT_TYPE_OPFLEX_OVS,
            'start_flag': True}

        # Initialize OVS Manager
        self.bridge_manager = ovs_manager.OvsManager().initialize(self.host,
                                                                  kwargs)
        # Stores port update notifications for processing in main rpc loop
        self.updated_ports = set()
        # Stores port delete notifications
        self.deleted_ports = set()
        # Stores VRF update notifications
        self.updated_vrf = set()
        self.setup_rpc()
        self.local_ip = kwargs['local_ip']
        self.polling_interval = kwargs['polling_interval']
        self.minimize_polling = kwargs['minimize_polling']
        self.ovsdb_monitor_respawn_interval = (kwargs.get(
            'ovsdb_monitor_respawn_interval') or
             constants.DEFAULT_OVSDBMON_RESPAWN)
        self.setup_report()
        self.supported_pt_network_types = [ofcst.TYPE_OPFLEX]

        # Initialize iteration counter
        self.iter_num = 0
        self.run_daemon_loop = True
        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()

        self.quitting_rpc_timeout = kwargs['quitting_rpc_timeout']
        # Initialize the Endpoint Manager.
        # TODO(ivar): make this component pluggable.
        self.ep_manager = ep_manager.EndpointFileManager().initialize(
            self.host, self.bridge_manager, kwargs)

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
            LOG.exception(_LE("Failed reporting state!"))

    def setup_rpc(self):
        self.agent_id = 'opflex-agent-%s' % cfg.CONF.host
        self.context = context.get_admin_context_without_session()
        # Set GBP rpc API
        self.of_rpc = GBPOvsPluginApi(rpc.TOPIC_OPFLEX)
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
                     [topics.SUBNET, topics.UPDATE]]
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

    def port_bound(self, port, net_uuid, network_type, physical_network,
                   fixed_ips, device_owner, ovs_restarted):
        # TODO(ivar): No flows are needed in OVS, and GBP details can now
        # be retrieved in a sane way. This methos probably is not needed
        # anymore
        mapping = port.gbp_details
        port.net_uuid = net_uuid
        port.device_owner = device_owner
        port.fixed_ips = fixed_ips
        if not mapping:
            # Mapping is empty, this port left the Opflex policy space.
            LOG.warn("Mapping for port %s is None, undeclaring the Endpoint",
                     port.vif_id)
            self.ep_manager.undeclare_endpoint(port.vif_id)
        elif network_type in self.supported_pt_network_types:
            if ((self.opflex_networks is None) or
                    (physical_network in self.opflex_networks)):
                # Endpoint Manager to process the EP info
                LOG.debug("Processing the endpoint mapping "
                          "for port %(port)s: \n mapping: %(mapping)s" % {
                              'port': port.vif_id, 'mapping': mapping})
                self.ep_manager.declare_endpoint(port, mapping)
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

    def port_unbound(self, vif_id):
        """Unbind port.

        :param vif_id: the id of the vif
        """
        self.ep_manager.undeclare_endpoint(vif_id)

    def port_dead(self, port):
        self.bridge_manager.port_dead(port)
        self.ep_manager.undeclare_endpoint(port.vif_id)

    def process_network_ports(self, port_info, ovs_restarted):
        resync_a = False
        resync_b = False
        # TODO(salv-orlando): consider a solution for ensuring notifications
        # are processed exactly in the same order in which they were
        # received. This is tricky because there are two notification
        # sources: the neutron server, and the ovs db monitor process
        # If there is an exception while processing security groups ports
        # will not be wired anyway, and a resync will be triggered
        # TODO(salv-orlando): Optimize avoiding applying filters unnecessarily
        # (eg: when there are no IP address changes)
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
                skipped_devices = self.treat_devices_added_or_updated(
                    devices_added_updated, ovs_restarted)
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
            except ovs.DeviceListRetrievalError:
                # Need to resync as there was an error with server
                # communication.
                LOG.exception(_LE("process_network_ports - iteration:%d - "
                                  "failure while retrieving port details "
                                  "from server"), self.iter_num)
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
        self.sg_agent.remove_devices_filter(devices)
        for device in devices:
            LOG.info(_LI("Attachment %s removed"), device)
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
        # TODO(ivar): use the acync model
        vrf_details_list = self.of_rpc.get_vrf_details_list(
            self.context, self.agent_id, vrf_update, self.host)
        for details in vrf_details_list:
            # REVISIT(ivar): this is not a public facing API, we will move to
            # the right method once the redesign is complete.
            self.ep_manager.vrf_info_to_file(details)

    def treat_devices_added_or_updated(self, devices, ovs_restarted):
        # TODO(ivar): Move this method in the ep manager

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
            # REVISIT(ivar): this is not a public facing API, we will move to
            # the right method once the redesign is complete.
            port = self.bridge_manager.int_br.get_vif_port_by_id(device)
            if not port:
                # The port disappeared and cannot be processed
                LOG.info(_("Port %s was not found on the integration bridge "
                           "and will therefore not be processed"), device)
                skipped_devices.append(device)
                # Delete EP file
                self.ep_manager.undeclare_endpoint(device)
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

    def treat_vif_port(self, vif_port, port_id, network_id, network_type,
                       physical_network, admin_state_up,
                       fixed_ips, device_owner, ovs_restarted):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware
        if not vif_port.ofport:
            LOG.warn(_LW("VIF port: %s has no ofport configured, "
                         "and might not be able to transmit"), vif_port.vif_id)
        if vif_port:
            if admin_state_up:
                self.port_bound(vif_port, network_id, network_type,
                                physical_network, fixed_ips, device_owner,
                                ovs_restarted)
            else:
                self.port_dead(vif_port)
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
        if elapsed < self.polling_interval:
            # TODO(ivar) use this polling time to apply incoming config
            # and verify timeouts
            time.sleep(self.polling_interval - elapsed)
        else:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
        self.iter_num = self.iter_num + 1

    def process_deleted_ports(self, port_info):
        # don't try to process removed ports as deleted ports since
        # they are already gone
        if 'removed' in port_info:
            self.deleted_ports -= port_info['removed']
        deleted_ports = list(self.deleted_ports)
        while self.deleted_ports:
            port_id = self.deleted_ports.pop()
            self.bridge_manager.process_deleted_port(port_id)
            self.port_unbound(port_id)
        # Flush firewall rules
        self.sg_agent.remove_devices_filter(deleted_ports)
        # Process deleted ports
        for port_id in port_info.get('removed', []):
            self.port_unbound(port_id)

    def rpc_loop(self, polling_manager):
        sync = True
        ports = set()
        updated_ports_copy = set()
        updated_vrf_copy = set()
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
                LOG.info(_LI("Agent out of sync with plugin!"))
                ports.clear()
                sync = False
                polling_manager.force_polling()
            ovs_status = self.bridge_manager.check_bridge_status()
            if ovs_status == constants.OVS_RESTARTED:
                self.bridge_manager.setup_integration_br()
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
                    LOG.exception(_LE("Error while processing VIF ports"))
                    # Put the ports back in self.updated_port
                    self.updated_ports |= updated_ports_copy
                    self.updated_vrf |= updated_vrf_copy
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
        self.updated_ports = set()
        reg_ports = (set() if ovs_restarted else ports)
        port_info = self.bridge_manager.scan_ports(
            reg_ports, updated_ports_copy)
        removed_eps = (self.ep_manager.get_registered_endpoints() -
                       port_info['current'])
        if removed_eps:
            port_info['removed'] = port_info.get('removed',
                                                 set()) | removed_eps
        updated_vrf_copy = self.updated_vrf
        self.updated_vrf = set()
        vrf_info = updated_vrf_copy & set(
            self.ep_manager.vrf_dict.keys())
        port_info['vrf_updated'] = vrf_info

        self.process_deleted_ports(port_info)
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
            sync = self.process_network_ports(port_info,
                                              ovs_restarted)
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
    agent_config = ovs.create_agent_config_map(conf)
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

    try:
        agent = GBPOpflexAgent(root_helper=cfg.CONF.AGENT.root_helper,
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
