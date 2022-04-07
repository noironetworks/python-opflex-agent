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

from unittest import mock
sys.modules["apicapi"] = mock.Mock()  # noqa
sys.modules["pyinotify"] = mock.Mock()  # noqa

from opflexagent import gbp_agent
from opflexagent import snat_iptables_manager
from opflexagent.test import base
from opflexagent.utils.ep_managers import endpoint_file_manager

from neutron.agent.linux import ip_lib
from neutron.api.rpc.callbacks import events
from neutron.conf.agent import dhcp as dhcp_config
from neutron.objects import trunk as trunk_obj
from neutron.plugins.ml2.drivers.openvswitch.agent import (
    ovs_neutron_agent as ovs)
from oslo_config import cfg
from oslo_utils import uuidutils

_uuid = uuidutils.generate_uuid
NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'
EP_DIR = '.%s_endpoints/'


class TestGBPOpflexAgent(base.OpflexTestBase):

    def setUp(self):
        cfg.CONF.register_opts(dhcp_config.DHCP_OPTS)
        super(TestGBPOpflexAgent, self).setUp()
        mock.patch('neutron.agent.ovsdb.impl_idl.api_factory').start()
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
        self.addCleanup(self.agent.bridge_manager.fabric_br.reset_mock)

        ip_lib.IPDevice = mock.Mock()

    def _try_port_binding_args(self, net_type='net_type'):
        port = mock.Mock()
        port.trunk_details = None
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
                'segmentation_id': ''}

    def _purge_endpoint_dir(self):
        try:
            shutil.rmtree(self.ep_dir)
        except OSError:
            pass

    def _initialize_agent(self):
        cfg.CONF.set_override('epg_mapping_dir', self.ep_dir, 'OPFLEX')
        kwargs = gbp_agent.create_agent_config_map(cfg.CONF)

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        resources = [
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
            mock.patch('neutron.agent.common.ovs_lib.BaseOVS.get_bridges'),
            mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall',
                new=MockFixedIntervalLoopingCall),
            mock.patch('opflexagent.gbp_agent.GBPOpflexAgent.'
                '_report_state')]

        with base.nested_context_manager(*resources):
            agent = gbp_agent.GBPOpflexAgent(**kwargs)
            # set back to true because initial report state will succeed due
            # to mocked out RPC calls
            agent.use_call = True
            agent.tun_br = mock.Mock()
            agent.host = 'host1'
        agent.sg_agent = mock.Mock()
        return agent

    def _mock_agent(self, agent):
        # Mock EP manager methods
        agent.ep_manager._write_endpoint_file = mock.Mock(
            return_value=agent.ep_manager.epg_mapping_file)
        agent.ep_manager._write_vrf_file = mock.Mock()
        agent.ep_manager._delete_endpoint_file = mock.Mock()
        agent.ep_manager._delete_vrf_file = mock.Mock()
        agent.ep_manager.snat_iptables = mock.Mock()
        agent.ep_manager.snat_iptables.setup_snat_for_es = mock.Mock(
            return_value=tuple([None, None]))
        agent.ep_manager._release_int_fip = mock.Mock()

        agent.opflex_networks = ['phys_net']
        # Mock bridge
        agent.bridge_manager.int_br = mock.Mock()
        agent.bridge_manager.int_br.get_vif_port_set = mock.Mock(
            return_value=set())
        agent.bridge_manager.add_patch_ports = mock.Mock()
        agent.bridge_manager.delete_patch_ports = mock.Mock()
        agent.bridge_manager.fabric_br = mock.Mock()
        agent.bridge_manager.trunk_rpc = mock.Mock()
        agent.of_rpc.get_gbp_details = mock.Mock()
        agent.port_manager.of_rpc.request_endpoint_details_list = mock.Mock()
        agent.notify_worker.terminate()

    def test_port_unbound_snat_cleanup(self):
        self.agent.int_br = mock.Mock()
        with mock.patch('neutron.agent.linux.ip_lib.IPDevice') as mock1:
            instance = mock1.return_value
            instance.link.address = 'foo-mac'
            mapping = self._get_gbp_details()
            self.agent.of_rpc.get_gbp_details.return_value = mapping
            setup_snat = self.agent.ep_manager.snat_iptables.setup_snat_for_es
            setup_snat.return_value = (
                tuple(['foo-if', 'foo-mac']))
            args_1 = self._try_port_binding_args('opflex')
            args_1['port'].gbp_details = mapping
            self.agent.try_port_binding(**args_1)

            instance.link.address = 'aa:bb:cc:00:11:44'
            args_2 = self._try_port_binding_args('opflex')
            args_2['port'].gbp_details = mapping

            setup_snat.return_value = (
                tuple(['foo-if', 'aa:bb:cc:00:11:44']))
            self.agent.try_port_binding(**args_2)
            self.assertEqual(
                1,
                self.agent.ep_manager.snat_iptables
                    .setup_snat_for_es.call_count)

            self.agent.port_unbound(args_1['port'].vif_id)
            self.assertFalse(
                self.agent.ep_manager.snat_iptables.cleanup_snat_for_es.called)

            self.agent.port_unbound(args_2['port'].vif_id)
            (self.agent.ep_manager.
                snat_iptables.cleanup_snat_for_es.assert_called_with('EXT-1'))
            self.agent.ep_manager._delete_endpoint_file.assert_called_with(
                'EXT-1')

    def test_try_port_binding_no_mapping(self):
        self.agent.int_br = mock.Mock()
        args = self._try_port_binding_args('opflex')
        args['port'].gbp_details = None
        self.agent.try_port_binding(**args)
        self.assertFalse(self.agent.int_br.set_db_attribute.called)
        self.assertFalse(self.agent.ep_manager._write_endpoint_file.called)

    def test_subnet_update(self):
        fake_sub = {'tenant_id': 'tenant-id', 'id': 'someid'}
        self.agent.subnet_update(mock.Mock(), fake_sub)
        self.assertEqual(set(['tenant-id']), self.agent.updated_vrf)

    def test_binding_activate(self):
        self.agent.binding_activate('context', port_id='id', host='host1')
        self.assertIn('id', self.agent.activated_bindings)

    def test_binding_activate_not_for_host(self):
        self.agent.binding_activate('context', port_id='id', host='other-host')
        self.assertEqual(set(), self.agent.activated_bindings)

    def test_process_activated_bindings(self):
        port_info = {}
        port_info['added'] = set(['added_port_id'])
        port_info['current'] = set(['activated_port_id'])
        self.agent.process_activated_bindings(port_info,
                                              set(['activated_port_id']))
        self.assertIn('added_port_id', port_info['added'])
        self.assertIn('activated_port_id', port_info['added'])

    def test_process_activated_bindings_activated_port_not_present(self):
        port_info = {}
        port_info['added'] = set(['added_port_id'])
        port_info['current'] = set()
        self.agent.process_activated_bindings(port_info,
                                              set(['activated_port_id']))
        self.assertIn('added_port_id', port_info['added'])
        self.assertNotIn('activated_port_id', port_info['added'])

    def test_binding_deactivate_not_for_host(self):
        self.agent.binding_deactivate('unused_context', port_id='id',
                                      host='other_host')
        self.assertEqual(set(), self.agent.deactivated_bindings)

    def test_binding_deactivate(self):
        self.agent.binding_deactivate('unused_context', port_id='id',
                                      host='host1')
        self.assertEqual(set(['id']), self.agent.deactivated_bindings)
        self.agent.process_deactivated_bindings(port_info={})
        self.assertEqual(set(), self.agent.deactivated_bindings)

    def test_binding_deactivate_removed_port(self):
        self.agent.binding_deactivate('unused_context', port_id='id',
                                      host='host1')
        self.assertEqual(set(['id']), self.agent.deactivated_bindings)
        self.agent.process_deactivated_bindings(
            port_info={'removed': {'id', }})
        self.assertEqual(set(), self.agent.deactivated_bindings)

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
        self.agent.bridge_manager.add_patch_ports = mock.Mock()
        fake_sub = {'tenant_id': 'tenant-id', 'id': 'someid'}

        mapping = self._get_gbp_details(l3_policy_id='tenant-id')
        self.agent.of_rpc.get_vrf_details_list = mock.Mock(
            return_value=[{'l3_policy_id': 'tenant-id',
                           'vrf_tenant': mapping['vrf_tenant'],
                           'vrf_name': mapping['vrf_name'],
                           'vrf_subnets': mapping['vrf_subnets'] +
                           ['1.1.1.0/24']}])

        args = self._try_port_binding_args('opflex')
        args['port'].gbp_details = mapping
        self.agent.try_port_binding(**args)
        self.agent.bridge_manager.add_patch_ports.assert_called_once_with(
            [args['port'].vif_id])
        self.agent.ep_manager._write_vrf_file.reset_mock()
        self.agent.subnet_update(mock.Mock(), fake_sub)

        port_info = self.agent.bridge_manager.scan_ports(set())
        port_info['vrf_updated'] = self.agent.updated_vrf
        port_info['added'] = set(['1', '2'])
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

    def test_stale_endpoints_in_process_network_ports(self):
        self.agent.ep_manager.undeclare_endpoint = mock.Mock()
        self.agent.plugin_rpc.update_device_down = mock.Mock()
        self.agent.ep_manager._stale_endpoints.add('EXT-2.ep')
        self.agent.process_network_ports({}, False)
        self.agent.ep_manager.undeclare_endpoint.assert_called_once_with(
            'EXT-2.ep')

    def test_dead_port(self):
        port = mock.Mock(ofport=1)
        self.agent.bridge_manager.int_br.get_vif_port_by_id = mock.Mock(
            return_value=port)
        with mock.patch.object(gbp_agent.ep_manager.EndpointFileManager,
                               'undeclare_endpoint'):
            self.agent.treat_devices_added_or_updated(
                {'device': 'some_device'})
            self.agent.ep_manager.undeclare_endpoint.assert_called_once_with(
                port.vif_id)

    def test_missing_port(self):
        self.agent.bridge_manager.int_br.get_vif_port_by_id = mock.Mock(
            return_value=None)
        with mock.patch.object(gbp_agent.ep_manager.EndpointFileManager,
                               'undeclare_endpoint'):
            self.agent.treat_devices_added_or_updated(
                {'device': 'some_device'})
            self.agent.ep_manager.undeclare_endpoint.assert_called_once_with(
                'some_device')

    def test_admin_disabled_port(self):
        # Set port's admin_state_up to False => mapping file should be removed
        mapping = self._get_gbp_details(device='some_device')
        port_details = {'device': 'some_device',
                        'admin_state_up': False,
                        'port_id': mapping['port_id'],
                        'network_id': 'some-net',
                        'network_type': 'opflex',
                        'physical_network': 'phys_net',
                        'segmentation_id': '',
                        'fixed_ips': [],
                        'device_owner': 'some-vm'}
        self.agent.plugin_rpc.update_device_up = mock.Mock()
        self.agent.plugin_rpc.update_device_down = mock.Mock()
        port = mock.Mock(ofport=1, vif_id=mapping['port_id'])
        self.agent.bridge_manager.int_br.get_vif_port_by_id = mock.Mock(
            return_value=port)
        self.agent.ep_manager._mapping_cleanup = mock.Mock()
        self.agent.ep_manager._mapping_to_file = mock.Mock()

        self.agent.treat_devices_added_or_updated(
            {'device': 'some_device', 'neutron_details': port_details,
             'gbp_details': mapping, 'port_id': 'port_id'})
        self.agent.ep_manager._mapping_cleanup.assert_called_once_with(
            mapping['port_id'])

        port_details['admin_state_up'] = True
        self.agent.treat_devices_added_or_updated(
            {'device': 'some_device', 'neutron_details': port_details,
             'gbp_details': mapping, 'port_id': 'port_id'})
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

        resources = [
            mock.patch.object(
                    snat_iptables_manager.SnatIptablesManager,
                    'cleanup_snat_all'),
            mock.patch.object(
                    snat_iptables_manager.SnatIptablesManager,
                    'check_if_exists', return_value=False),
            mock.patch.object(
                    endpoint_file_manager.EndpointFileManager,
                    'undeclare_endpoint'),
            mock.patch.object(ovs.OVSPluginApi, 'update_device_down')]

        with base.nested_context_manager(*resources):
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
        self.agent.bridge_manager.delete_patch_ports = mock.Mock()

        resources = [
            mock.patch.object(
                    snat_iptables_manager.SnatIptablesManager,
                    'cleanup_snat_all'),
            mock.patch.object(
                    endpoint_file_manager.EndpointFileManager,
                    'undeclare_endpoint'),
            mock.patch.object(ovs.OVSPluginApi, 'update_device_down')]

        with base.nested_context_manager(*resources):
            agent = self._initialize_agent()
            self._mock_agent(agent)
            port_info = {'current': set(['1', '2']),
                         'removed': set(['3', '5'])}
            agent.bridge_manager.scan_ports = mock.Mock(return_value=port_info)
            agent.bridge_manager.delete_patch_ports = mock.Mock()
            agent.deleted_ports.add('3')
            agent.deleted_ports.add('4')
            port_stats = {'regular': {'added': 0,
                                      'updated': 0,
                                      'removed': 0},
                          'ancillary': {'added': 0,
                                        'removed': 0}}
            agent._main_loop(set(), True, 1, port_stats, mock.Mock(), True)
            # 3, 4 and 5 are undeclared once
            expected = [mock.call('3'), mock.call('4'), mock.call('5')]
            self._check_call_list(
                expected,
                agent.ep_manager.undeclare_endpoint.call_args_list)
            expected = [mock.call(['3']), mock.call(['4']), mock.call(['5'])]
            self._check_call_list(
                expected,
                agent.bridge_manager.delete_patch_ports.call_args_list)

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

        args = self._try_port_binding_args('opflex')
        args['port'].gbp_details = mapping
        self.agent.ep_manager._write_vrf_file = mock.Mock()
        self.agent.try_port_binding(**args)
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

    def test_apply_config_interval(self):
        self.assertEqual(0.5, self.agent.config_apply_interval)

    def test_trunk_handler(self):
        port = mock.Mock()
        port.vif_id = uuidutils.generate_uuid()
        trunk_id = uuidutils.generate_uuid()
        subports = [
            trunk_obj.SubPort(
                port_id=uuidutils.generate_uuid(), trunk_id=trunk_id,
                segmentation_type='foo', segmentation_id=i)
            for i in range(2)]
        trunk_details = {}
        trunk_details['trunk_id'] = trunk_id
        trunk_details['master_port_id'] = port.vif_id
        trunk_details['subports'] = subports
        port.trunk_details = trunk_details

        self.agent.bridge_manager.handle_subports(
            None, None, subports, events.CREATED)
        self.agent.bridge_manager.handle_subports(
            None, None, subports, events.DELETED)
        self.assertFalse(self.agent.bridge_manager.add_patch_ports.called)
        self.assertFalse(self.agent.bridge_manager.delete_patch_ports.called)

        def binding_call(context, subports):
            return {trunk_id: [{'id': x.port_id, 'mac_address': '%s' % i}
                               for i, x in enumerate(subports)]}
        self.agent.bridge_manager.trunk_rpc.update_subport_bindings = (
            binding_call)

        self.agent.bridge_manager.manage_trunk(port)
        self.agent.bridge_manager.unmanage_trunk(port.vif_id)

        self.agent.bridge_manager.add_patch_ports.assert_called_with(
            [subports[0].port_id, subports[1].port_id],
            attached_macs={subports[0].port_id: '0', subports[1].port_id: '1'})

        call_args = self.agent.bridge_manager.delete_patch_ports.call_args
        self.assertEqual(set(call_args[0][0]),
            set([subports[0].port_id, subports[1].port_id]))

    def _test_port_bound_to_host(self, net_type, svi=False):
        if net_type is 'vlan':
            vlan_info = {}
            vlan_info['device'] = 'some_device'
            if svi:
                vlan_info['svi'] = True
            vlan_info['endpoint_group_name'] = 'svi-net-id'
            mapping = self._get_gbp_details(**vlan_info)
        else:
            mapping = self._get_gbp_details(device='some_device')
        seg_id = 1234 if net_type is 'vlan' else ''
        port_details = {'device': 'some_device',
                        'admin_state_up': True,
                        'port_id': mapping['port_id'],
                        'network_id': 'some-net',
                        'network_type': net_type,
                        'physical_network': 'phys_net',
                        'segmentation_id': seg_id,
                        'fixed_ips': [],
                        'device_owner': 'some-vm'}
        self.agent.plugin_rpc.update_device_up = mock.Mock()
        self.agent.plugin_rpc.update_device_down = mock.Mock()
        port = mock.Mock(ofport=1, vif_id=mapping['port_id'])
        self.agent.bridge_manager.int_br.get_vif_port_by_id = mock.Mock(
            return_value=port)
        self.agent.ep_manager._mapping_cleanup = mock.Mock()
        self.agent.ep_manager._mapping_to_file = mock.Mock()

        # first test is with no binding attribute. This is what
        # happens when port binding is first attempted, in order to
        # bind the port to a host.
        mapping['host'] = ''
        self.agent.treat_devices_added_or_updated(
            {'device': 'some_device', 'neutron_details': port_details,
             'gbp_details': mapping, 'port_id': 'port_id'})
        epargs = self.agent.ep_manager._mapping_to_file.call_args_list

        self.assertEqual(port_details['network_type'],
            epargs[0][0][0].network_type)
        if net_type is 'vlan':
            self.assertEqual(port_details['segmentation_id'],
                epargs[0][0][0].segmentation_id)
            if svi:
                self.assertEqual(True, epargs[0][0][1].get('svi'))
                self.assertEqual(vlan_info['endpoint_group_name'],
                    epargs[0][0][1].get('endpoint_group_name'))
            else:
                self.assertIsNone(epargs[0][0][1].get('svi'))
                self.assertEqual(mapping['endpoint_group_name'],
                    epargs[0][0][1].get('endpoint_group_name'))
        else:
            self.assertIsNone(epargs[0][0][1].get('svi'))
            self.assertEqual(mapping['endpoint_group_name'],
                epargs[0][0][1].get('endpoint_group_name'))
            self.assertEqual('', epargs[0][0][0].segmentation_id)

        self.agent.ep_manager._mapping_cleanup.assert_called_once_with(
            port_details['port_id'], cleanup_vrf=False,
            mac_exceptions=set([mapping['mac_address']]))

        self.agent.ep_manager._mapping_cleanup.reset_mock()
        self.agent.ep_manager._mapping_to_file.reset_mock()

        # Now try binding with a different host
        mapping['host'] = 'host2'
        self.agent.treat_devices_added_or_updated(
            {'device': 'some_device', 'neutron_details': port_details,
             'gbp_details': mapping, 'port_id': 'port_id'})
        self.assertFalse(self.agent.ep_manager._mapping_to_file.called)
        self.agent.ep_manager._mapping_cleanup.assert_called_once_with(
            port_details['device'])

    def test_port_bound_to_host_net_opflex(self):
        self._test_port_bound_to_host('opflex')

    def test_port_bound_to_host_net_vlan(self):
        self._test_port_bound_to_host('vlan')

    def test_port_bound_to_host_net_vlan_svi(self):
        self._test_port_bound_to_host('vlan', svi=True)

    def test_vrf_update(self):
        fake_vrf = 'coke-tenant coke-vrf'
        self.agent.opflex_notify_vrf(mock.Mock(), fake_vrf)
        self.assertEqual(set(['coke-tenant coke-vrf']), self.agent.updated_vrf)
