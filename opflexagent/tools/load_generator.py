# Copyright (c) 2018 Cisco Systems Inc.
# All Rights Reserved.
#
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

from neutron.common import eventlet_utils
eventlet_utils.monkey_patch()

import copy
import logging
import signal
import sys
import time

from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.plugins.ml2.drivers.openvswitch.agent import (
    ovs_neutron_agent as ovs)
from neutron_lib import context
from oslo_config import cfg
import click
from click import exceptions as exc

from opflexagent import config as ofcfg  # noqa
from opflexagent import constants as ofcst
from opflexagent import rpc
from opflexagent.utils.port_managers import async_port_manager as port_manager

LOG = logging.getLogger(__name__)


class LoadGenerator(rpc.OpenstackRpcMixin):

    def __init__(self, *args, **kwargs):
        self.opflex_networks = None
        self.restart_timeout = kwargs['restart_timeout']
        host_id = kwargs['host_id']
        self.host = host_id or cfg.CONF.host
        agent_conf = cfg.CONF.AGENT
        ovs_conf = cfg.CONF.OVS

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
        self.supported_pt_network_types = [ofcst.TYPE_OPFLEX]

        # Initialize iteration counter
        self.iter_num = 0
        self.run_daemon_loop = True
        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()
        self.quitting_rpc_timeout = agent_conf.quitting_rpc_timeout
        self.port_manager = port_manager.AsyncPortManager().initialize(
            self.host, self, kwargs)
        self.curr_ports = kwargs.get('curr_ports', set())
        self.registered_ports = set()
        self.dead_ports = set()
        self.processed_ports = set()

    def setup_rpc(self):
        # Set GBP rpc API
        self.agent_id = 'opflex-agent-%s' % cfg.CONF.host
        self.of_rpc = rpc.GBPServerRpcApi(rpc.TOPIC_OPFLEX)
        self.plugin_rpc = ovs.OVSPluginApi(topics.PLUGIN)

        self.topic = topics.AGENT
        self.endpoints = [self]
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.PORT, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [topics.SUBNET, topics.UPDATE],
                     [rpc.TOPIC_OPFLEX, rpc.VRF, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(
            self.endpoints, self.topic, consumers, start_listening=False)

    def process_vrf_update(self, vrf_update):
        ctx = context.get_admin_context_without_session()
        vrf_details_list = self.of_rpc.get_vrf_details_list(
            ctx, self.agent_id, vrf_update, self.host)
        for details in vrf_details_list:
            LOG.info("Declared VRF %s" % details['l3_policy_id'])

    def _info_has_changes(self, port_info):
        return (port_info.get('added') or
                port_info.get('removed') or
                port_info.get('updated') or
                port_info.get('vrf_updated'))

    def port_bound(self, port_id):
        # Could write EP file here
        self.processed_ports.add(port_id)
        LOG.info("Declared endpoint %s" % port_id)

    def port_unbound(self, port_id):
        self.processed_ports.discard(port_id)
        LOG.info("Undeclared endpoint %s" % port_id)

    def treat_devices_added_or_updated(self, details):
        if details.get('neutron_details', {}).get('port_id'):
            self.port_bound(details['device'])
        else:
            LOG.warning("Dead port: %s" % details['device'])
            self.dead_ports.add(details['device'])

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
        new_start = time.time()
        if new_start - self.initial_start > self.restart_timeout:
            LOG.info("Resetting agent.")
            self.initial_start = new_start
            self.registered_ports.clear()
            self.dead_ports.clear()

    def rpc_loop(self):
        self.initial_start = time.time()
        while self.run_daemon_loop:
            start = time.time()
            port_stats = {'regular': {'added': 0,
                                      'updated': 0,
                                      'removed': 0},
                          'ancillary': {'added': 0,
                                        'removed': 0}}
            LOG.debug("Agent rpc_loop - iteration:%d started",
                      self.iter_num)
            try:
                self._main_loop(start, port_stats)
            except Exception:
                LOG.exception("Error while processing VIF ports")

            self.loop_count_and_wait(start, port_stats)

    def _get_ports(self):
        port_info = {'current': copy.deepcopy(self.curr_ports),
                     'added': self.curr_ports - self.registered_ports,
                     'removed': self.registered_ports - self.curr_ports}
        return port_info

    def _main_loop(self, start, port_stats):
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
            port_info = self._get_ports()
            port_info['removed'] = port_info.get(
                'removed', set()) | deleted_ports_copy

            vrf_info = updated_vrf_copy
            port_info['vrf_updated'] = vrf_info
            LOG.debug("Agent rpc_loop - iteration:%(iter_num)d - "
                      "port information retrieved. "
                      "Elapsed:%(elapsed).3f",
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
            # Secure and wire/unwire VIFs and update their status
            # on Neutron server
            if self._info_has_changes(port_info):
                LOG.debug("Starting to process devices in:%s",
                          port_info)
                # If treat devices fails - must resync with plugin
                self.process_network_ports(port_info)
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
            self.registered_ports = port_info['current']
        except Exception:
            self.updated_ports |= updated_ports_copy
            self.deleted_ports |= deleted_ports_copy
            self.updated_vrf |= updated_vrf_copy
            raise

    def process_network_ports(self, port_info):
        # Schedule GBP requests
        self.port_manager.schedule_update(port_info['added'])

    def daemon_loop(self):
        self.rpc_loop()

    def _handle_sigterm(self, signum, frame):
        LOG.debug("Agent caught SIGTERM, quitting daemon loop.")
        self.run_daemon_loop = False
        if self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)

    def set_rpc_timeout(self, timeout):
        for rpc_api in (self.plugin_rpc,):
            rpc_api.client.timeout = timeout


def create_agent_config_map(conf):
    agent_config = {}
    agent_config['epg_mapping_dir'] = conf.OPFLEX.epg_mapping_dir
    agent_config['opflex_networks'] = conf.OPFLEX.opflex_networks
    agent_config['endpoint_request_timeout'] = (
        conf.OPFLEX.endpoint_request_timeout)
    agent_config['config_apply_interval'] = conf.OPFLEX.config_apply_interval
    return agent_config


def main(curr_ports=None, endpoint_request_timeout=None, restart_timeout=None,
         host_id=None):
    curr_ports = curr_ports or set()
    n_rpc.init(cfg.CONF)

    agent_config = create_agent_config_map(cfg.CONF)
    if endpoint_request_timeout:
        agent_config['endpoint_request_timeout'] = endpoint_request_timeout
    if restart_timeout:
        agent_config['restart_timeout'] = restart_timeout
    if host_id:
        agent_config['host_id'] = host_id

    agent = LoadGenerator(curr_ports=curr_ports, **agent_config)
    signal.signal(signal.SIGTERM, agent._handle_sigterm)
    if not agent:
        sys.exit(1)

    LOG.info(_("Load generator initialized successfully, now running... "))
    agent.daemon_loop()


@click.group()
@click.option('--config-file', '-c', multiple=True,
              help='Neutron opflex agent static configuration file')
@click.option('--debug', '-d', is_flag=True, default=False)
def opflex_load_generator(config_file, debug):
    """Group for AIM cli."""
    args = []
    if config_file:
        for file in config_file:
            args += ['--config-file', file]
    cfg.CONF(project='opflex-load-generator', args=args)
    if not cfg.CONF.config_file:
        raise exc.UsageError(
            "Unable to find configuration file via the "
            "'--config-file' option %s!" % config_file)
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


@opflex_load_generator.command(name='run')
@click.argument('port_file', required=True)
@click.option('--host-id', '-h', help='Agent host ID (if not set, '
                                      'uses config file value)')
@click.option('--request-timeout', '-r', help='Request timeout (if not set, '
                                              'uses config file value)')
@click.option('--restart-timeout', '-R', default=300, help='Restart timeout')
def db_migration(port_file, host_id, request_timeout, restart_timeout):
    ports = set()
    with open(port_file) as f:
        for port_id in f:
            port_id = port_id.strip(' \n')
            ports.add(port_id)
    try:
        main(curr_ports=ports, endpoint_request_timeout=request_timeout,
             restart_timeout=restart_timeout, host_id=host_id)
    except Exception:
        import traceback
        click.echo(traceback.format_exc())


def run():
    opflex_load_generator(auto_envvar_prefix='OPFLEX_LOAD')


if __name__ == "__main__":
    run()

