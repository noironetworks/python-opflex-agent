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

import shutil
import sys

import mock
sys.modules["apicapi"] = mock.Mock()
sys.modules["pyinotify"] = mock.Mock()

import contextlib
from opflexagent import gbp_ovs_agent
from opflexagent import snat_iptables_manager
from opflexagent.test import base
from opflexagent.utils.ep_managers import endpoint_file_manager

from neutron.agent.dhcp import config as dhcp_config
from oslo_config import cfg
from oslo_utils import uuidutils

_uuid = uuidutils.generate_uuid
NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'
EP_DIR = '.%s_endpoints/'


class TestGBPOpflexAgent(base.OpflexTestBase):

    def setUp(self):
        cfg.CONF.register_opts(dhcp_config.DHCP_OPTS)
        super(TestGBPOpflexAgent, self).setUp()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_default('quitting_rpc_timeout', 10, 'AGENT')
        self.ep_dir = EP_DIR % _uuid()
        self.agent = self._initialize_agent()
        self._mock_agent(self.agent)
        self.addCleanup(self._purge_endpoint_dir)
        self.addCleanup(self.agent.bridge_manager.int_br.reset_mock)
        self.addCleanup(self.agent.of_rpc.get_gbp_details)

    def _port_bound_args(self, net_type='net_type'):
        port = mock.Mock()
        port.vif_id = uuidutils.generate_uuid()
        return {'port': port,
                'net_uuid': 'net_id',
                'network_type': net_type,
                'physical_network': 'phys_net',
                'fixed_ips': [{'subnet_id': 'id1',
                               'ip_address': '192.168.0.2'},
                              {'subnet_id': 'id2',
                               'ip_address': '192.168.1.2'}],
                'device_owner': 'compute:',
                'ovs_restarted': True}

    def _purge_endpoint_dir(self):
        try:
            shutil.rmtree(self.ep_dir)
        except OSError:
            pass

    def _initialize_agent(self):
        cfg.CONF.set_override('epg_mapping_dir', self.ep_dir, 'OPFLEX')
        kwargs = gbp_ovs_agent.create_agent_config_map(cfg.CONF)

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        with contextlib.nested(
            mock.patch('opflexagent.utils.bridge_managers.ovs_manager.'
                       'OvsManager.setup_integration_bridge',
                       return_value=mock.Mock()),
            mock.patch('neutron.agent.common.ovs_lib.OVSBridge.'
                       'create'),
            mock.patch('neutron.agent.common.ovs_lib.OVSBridge.'
                       'set_secure_mode'),
            mock.patch('neutron.agent.common.ovs_lib.OVSBridge.'
                       'get_local_port_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.common.ovs_lib.BaseOVS.get_bridges'),
            mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall),
            mock.patch('opflexagent.gbp_ovs_agent.GBPOpflexAgent.'
                       '_report_state')):
            agent = gbp_ovs_agent.GBPOpflexAgent(**kwargs)
            # set back to true because initial report state will succeed due
            # to mocked out RPC calls
            agent.use_call = True
            agent.tun_br = mock.Mock()
        agent.sg_agent = mock.Mock()
        return agent

    def _mock_agent(self, agent):
        # Mock EP manager methods
        agent.ep_manager._write_endpoint_file = mock.Mock()
        agent.ep_manager._write_vrf_file = mock.Mock()
        agent.ep_manager._delete_endpoint_file = mock.Mock()
        agent.ep_manager._delete_vrf_file = mock.Mock()
        agent.ep_manager.snat_iptables = mock.Mock()
        agent.ep_manager.snat_iptables.setup_snat_for_es = mock.Mock(
            return_value = tuple([None, None]))
        agent.ep_manager._release_int_fip = mock.Mock()

        agent.opflex_networks = ['phys_net']
        # Mock bridge
        agent.bridge_manager.int_br = mock.Mock()
        agent.bridge_manager.int_br.get_vif_port_set = mock.Mock(
            return_value=set())
        agent.of_rpc.get_gbp_details = mock.Mock()
        agent.notify_worker.terminate()

    def test_port_unbound_snat_cleanup(self):
        self.agent.int_br = mock.Mock()

        mapping = self._get_gbp_details()
        self.agent.of_rpc.get_gbp_details.return_value = mapping
        self.agent.ep_manager.snat_iptables.setup_snat_for_es.return_value = (
            tuple(['foo-if', 'foo-mac']))
        args_1 = self._port_bound_args('opflex')
        args_1['port'].gbp_details = mapping
        self.agent.port_bound(**args_1)

        args_2 = self._port_bound_args('opflex')
        args_2['port'].gbp_details = mapping
        self.agent.port_bound(**args_2)
        self.assertEqual(
            1,
            self.agent.ep_manager.snat_iptables.setup_snat_for_es.call_count)

        self.agent.port_unbound(args_1['port'].vif_id)
        self.assertFalse(
            self.agent.ep_manager.snat_iptables.cleanup_snat_for_es.called)

        self.agent.port_unbound(args_2['port'].vif_id)
        (self.agent.ep_manager.
            snat_iptables.cleanup_snat_for_es.assert_called_with('EXT-1'))
        self.agent.ep_manager._delete_endpoint_file.assert_called_with('EXT-1')

    def test_port_bound_no_mapping(self):
        self.agent.int_br = mock.Mock()
        self.agent.of_rpc.get_gbp_details.return_value = None
        args = self._port_bound_args('opflex')
        args['port'].gbp_details = None
        self.agent.port_bound(**args)
        self.assertFalse(self.agent.int_br.set_db_attribute.called)
        self.assertFalse(self.agent.ep_manager._write_endpoint_file.called)

    def test_subnet_update(self):
        fake_sub = {'tenant_id': 'tenant-id', 'id': 'someid'}
        self.agent.subnet_update(mock.Mock(), fake_sub)
        self.assertEqual(set(['tenant-id']), self.agent.updated_vrf)

    def test_subnet_has_updates(self):
        fake_sub = {'tenant_id': 'tenant-id', 'id': 'someid'}
        polling_manager = mock.Mock()
        polling_manager.is_polling_required = False
        self.agent.sg_agent.firewall_refresh_needed = mock.Mock(
            return_value=False)
        self.assertFalse(self.agent._agent_has_updates(polling_manager))
        self.agent.subnet_update(mock.Mock(), fake_sub)
        self.assertTrue(self.agent._agent_has_updates(polling_manager))

    def test_process_network_ports(self):
        fake_sub = {'tenant_id': 'tenant-id', 'id': 'someid'}

        mapping = self._get_gbp_details(l3_policy_id='tenant-id')
        self.agent.of_rpc.get_gbp_details.return_value = mapping
        self.agent.of_rpc.get_vrf_details_list = mock.Mock(
            return_value=[{'l3_policy_id': 'tenant-id',
                           'vrf_tenant': mapping['vrf_tenant'],
                           'vrf_name': mapping['vrf_name'],
                           'vrf_subnets': mapping['vrf_subnets'] +
                           ['1.1.1.0/24']}])

        args = self._port_bound_args('opflex')
        args['port'].gbp_details = mapping
        self.agent.port_bound(**args)
        self.agent.ep_manager._write_vrf_file.reset_mock()
        self.agent.subnet_update(mock.Mock(), fake_sub)

        port_info = self.agent.bridge_manager.scan_ports(set())
        port_info['vrf_updated'] = self.agent.updated_vrf
        self.agent.process_network_ports(port_info, False)
        self.agent.of_rpc.get_vrf_details_list.assert_called_once_with(
            mock.ANY, mock.ANY, set(['tenant-id']), mock.ANY)
        self.agent.ep_manager._write_vrf_file.assert_called_once_with(
            'tenant-id', {
                "domain-policy-space": mapping['vrf_tenant'],
                "domain-name": mapping['vrf_name'],
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16',
                                            '1.1.1.0/24',
                                            '169.254.0.0/16'])})

    def test_dead_port(self):
        self.agent.of_rpc.get_gbp_details_list = mock.Mock(
            return_value=[{'device': 'some_device'}])
        self.agent.plugin_rpc.get_devices_details_list = mock.Mock(
            return_value=[{'device': 'some_device', 'port_id': 'portid'}])
        port = mock.Mock(ofport=1)
        self.agent.bridge_manager.int_br.get_vif_port_by_id = mock.Mock(
            return_value=port)

        self.agent.bridge_manager.port_dead = mock.Mock()
        self.agent.treat_devices_added_or_updated(['some_device'], True)
        self.agent.bridge_manager.port_dead.assert_called_once_with(port)

    def test_missing_port(self):
        self.agent.of_rpc.get_gbp_details_list = mock.Mock(
            return_value=[{'device': 'some_device'}])
        self.agent.plugin_rpc.get_devices_details_list = mock.Mock(
            return_value=[{'device': 'some_device', 'port_id': 'portid'}])
        self.agent.bridge_manager.int_br.get_vif_port_by_id = mock.Mock(
            return_value=None)
        with mock.patch.object(gbp_ovs_agent.ep_manager.EndpointFileManager,
                               'undeclare_endpoint'):
            self.agent.treat_devices_added_or_updated(['some_device'], True)
            self.agent.ep_manager.undeclare_endpoint.assert_called_once_with(
                'some_device')

    def test_admin_disabled_port(self):
        # Set port's admin_state_up to False => mapping file should be removed
        mapping = self._get_gbp_details(device='some_device')
        self.agent.of_rpc.get_gbp_details_list = mock.Mock(
            return_value=[mapping])
        port_details = {'device': 'some_device',
                        'admin_state_up': False,
                        'port_id': mapping['port_id'],
                        'network_id': 'some-net',
                        'network_type': 'opflex',
                        'physical_network': 'phys_net',
                        'segmentation_id': '',
                        'fixed_ips': [],
                        'device_owner': 'some-vm'}
        self.agent.plugin_rpc.get_devices_details_list = mock.Mock(
            return_value=[port_details])
        self.agent.plugin_rpc.update_device_up = mock.Mock()
        self.agent.plugin_rpc.update_device_down = mock.Mock()
        port = mock.Mock(ofport=1, vif_id=mapping['port_id'])
        self.agent.bridge_manager.int_br.get_vif_port_by_id = mock.Mock(
            return_value=port)
        self.agent.ep_manager._mapping_cleanup = mock.Mock()
        self.agent.ep_manager._mapping_to_file = mock.Mock()

        self.agent.treat_devices_added_or_updated(['some_device'], False)
        self.agent.ep_manager._mapping_cleanup.assert_called_once_with(
            mapping['port_id'])

        port_details['admin_state_up'] = True
        self.agent.treat_devices_added_or_updated(['some_device'], False)
        self.assertTrue(self.agent.ep_manager._mapping_to_file.called)

    def test_stale_endpoints(self):
        self.agent.ep_manager._write_file(
            'uuid1_AA', {}, self.agent.ep_manager.epg_mapping_file)
        self.agent.ep_manager._write_file(
            'uuid1_BB', {}, self.agent.ep_manager.epg_mapping_file)
        self.agent.ep_manager._write_file(
            'uuid1_CC', {}, self.agent.ep_manager.epg_mapping_file)
        self.agent.ep_manager._write_file(
            'uuid2_BB', {}, self.agent.ep_manager.epg_mapping_file)
        self.agent.ep_manager._write_file(
            'uuid2_BB', {}, self.agent.ep_manager.epg_mapping_file)
        with contextlib.nested(
                mock.patch.object(
                    snat_iptables_manager.SnatIptablesManager,
                    'cleanup_snat_all'),
                mock.patch.object(
                    endpoint_file_manager.EndpointFileManager,
                    'undeclare_endpoint')):
            port_stats = {'regular': {'added': 0,
                                      'updated': 0,
                                      'removed': 0},
                          'ancillary': {'added': 0,
                                        'removed': 0}}
            agent = self._initialize_agent()
            self._mock_agent(agent)
            agent.bridge_manager.int_br.get_vif_port_set = mock.Mock(
                return_value=set(['uuid1']))
            agent._main_loop(set(), True, 1, port_stats, mock.Mock(), True)
            agent.ep_manager.undeclare_endpoint.assert_called_once_with(
                'uuid2')

    def test_process_deleted_ports(self):
        with mock.patch.object(
                endpoint_file_manager.EndpointFileManager,
                'undeclare_endpoint'):
            port_info = {'current': set(['1', '2']),
                         'removed': set(['3', '5'])}
            self.agent.deleted_ports.add('3')
            self.agent.deleted_ports.add('4')
            self.agent.process_deleted_ports(port_info)
            # 3, 4 and 5 are undeclared once
            expected = [mock.call('3'), mock.call('4'), mock.call('5')]
            self._check_call_list(
                expected,
                self.agent.ep_manager.undeclare_endpoint.call_args_list)

            self.agent.ep_manager.undeclare_endpoint.reset_mock()
            port_info = {'current': set(['1', '2'])}
            self.agent.process_deleted_ports(port_info)
            # Nothing to do
            self.assertFalse(self.agent.ep_manager.undeclare_endpoint.called)

    def test_process_vrf_update(self):
        self.agent.ep_manager._delete_vrf_file = mock.Mock()
        self.agent.of_rpc.get_vrf_details_list = mock.Mock(
            return_value=[{'l3_policy_id': 'tenant-id',
                           'vrf_tenant': 'tn-tenant',
                           'vrf_name': 'ctx'}])
        self.agent.process_vrf_update(set(['tenant_id']))
        # not called because VRF is not owned
        self.assertFalse(self.agent.ep_manager._delete_vrf_file.called)

        # now create a port for this vrf
        mapping = self._get_gbp_details(l3_policy_id='tenant-id')
        self.agent.of_rpc.get_gbp_details.return_value = mapping

        args = self._port_bound_args('opflex')
        args['port'].gbp_details = mapping
        self.agent.ep_manager._write_vrf_file = mock.Mock()
        self.agent.port_bound(**args)
        self.agent.ep_manager._write_vrf_file.assert_called_once_with(
            'tenant-id', {
                "domain-policy-space": mapping['vrf_tenant'],
                "domain-name": mapping['vrf_name'],
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16',
                                            '169.254.0.0/16'])})
        self.assertFalse(self.agent.ep_manager._delete_vrf_file.called)

        # Now simulate a deletion
        self.agent.process_vrf_update(set(['tenant_id']))
        self.agent.ep_manager._delete_vrf_file.assert_called_once_with(
            'tenant-id')
