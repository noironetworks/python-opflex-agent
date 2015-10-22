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

import contextlib
from opflexagent import gbp_ovs_agent

from neutron.agent.linux import dhcp
from neutron.openstack.common import uuidutils
from neutron.tests import base
from oslo.config import cfg

_uuid = uuidutils.generate_uuid
NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'
EP_DIR = '.%s_endpoints/'


class TestGbpOvsAgent(base.BaseTestCase):

    def setUp(self):
        cfg.CONF.register_opts(dhcp.OPTS)
        super(TestGbpOvsAgent, self).setUp()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        self.ep_dir = EP_DIR % _uuid()
        self.agent = self._initialize_agent()
        self.agent._write_endpoint_file = mock.Mock()
        self.agent._write_vrf_file = mock.Mock()
        self.agent._delete_endpoint_file = mock.Mock()
        self.agent._delete_vrf_file = mock.Mock()
        self.agent.opflex_networks = ['phys_net']
        self.agent.int_br = mock.Mock()
        self.agent.int_br.get_vif_port_set = mock.Mock(return_value=set())
        self.agent.provision_local_vlan = mock.Mock()
        self.agent.of_rpc.get_gbp_details = mock.Mock()
        self.addCleanup(self._purge_endpoint_dir)
        self.addCleanup(self.agent.provision_local_vlan.reset_mock)
        self.addCleanup(self.agent.int_br.reset_mock)
        self.addCleanup(self.agent.of_rpc.get_gbp_details)

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
            mock.patch('opflexagent.gbp_ovs_agent.GBPOvsAgent.'
                       'setup_integration_br',
                       return_value=mock.Mock()),
            mock.patch('opflexagent.gbp_ovs_agent.GBPOvsAgent.'
                       'setup_ancillary_bridges',
                       return_value=[]),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'create'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'set_secure_mode'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'get_local_port_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.ovs_lib.'
                       'get_bridges'),
            mock.patch('neutron.openstack.common.loopingcall.'
                       'FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall)):
            agent = gbp_ovs_agent.GBPOvsAgent(**kwargs)
            # set back to true because initial report state will succeed due
            # to mocked out RPC calls
            agent.use_call = True
            agent.tun_br = mock.Mock()
        agent.sg_agent = mock.Mock()
        return agent

    def _get_gbp_details(self, **kwargs):
        pattern = {'port_id': 'port_id',
                   'mac_address': 'aa:bb:cc:00:11:22',
                   'ptg_id': 'ptg_id',
                   'segmentation_id': None,
                   'network_type': None,
                   'l2_policy_id': 'l2p_id',
                   'l3_policy_id': 'l3p_id',
                   'tenant_id': 'tenant_id',
                   'host': 'host1',
                   'ptg_tenant': 'apic_tenant',
                   'endpoint_group_name': 'epg_name',
                   'promiscuous_mode': False,
                   'vm-name': 'somename',
                   'app_profile_name': 'prof_name',
                   'extra_ips': ['192.169.8.1', '192.169.8.254'],
                   'vrf_name': 'name_of_l3p',
                   'vrf_tenant': 'apic_tenant',
                   'vrf_subnets': ['192.168.0.0/16', '192.169.0.0/16'],
                   'floating_ip': [{'id': '1',
                                    'floating_ip_address': '172.10.0.1',
                                    'floating_network_id': 'ext_net',
                                    'router_id': 'ext_rout',
                                    'port_id': 'port_id',
                                    'fixed_ip_address': '192.168.0.2',
                                    'nat_epg_tenant': 'nat-epg-tenant',
                                    'nat_epg_name': 'nat-epg-name'},
                                   {'id': '2',
                                    'floating_ip_address': '172.10.0.2',
                                    'floating_network_id': 'ext_net',
                                    'router_id': 'ext_rout',
                                    'port_id': 'port_id',
                                    'fixed_ip_address': '192.168.1.2'}],
                   'owned_addresses': ['192.168.0.2']}
        pattern.update(**kwargs)
        return pattern

    def _port_bound_args(self, net_type='net_type'):
        port = mock.Mock()
        port.vif_id = uuidutils.generate_uuid()
        return {'port': port,
                'net_uuid': 'net_id',
                'network_type': net_type,
                'physical_network': 'phys_net',
                'segmentation_id': 1000,
                'fixed_ips': [{'subnet_id': 'id1',
                               'ip_address': '192.168.0.2'},
                              {'subnet_id': 'id2',
                               'ip_address': '192.168.1.2'}],
                'device_owner': 'compute:',
                'ovs_restarted': True}

    def test_port_bound(self):
        self.agent.int_br = mock.Mock()
        mapping = self._get_gbp_details()
        self.agent.of_rpc.get_gbp_details.return_value = mapping
        args = self._port_bound_args('opflex')
        args['port'].gbp_details = mapping
        self.agent.port_bound(**args)
        self.agent.int_br.clear_db_attribute.assert_called_with(
            "Port", mock.ANY, "tag")
        self.assertFalse(self.agent.provision_local_vlan.called)
        self.agent._write_endpoint_file.assert_called_with(
            args['port'].vif_id + '_' + mapping['mac_address'], {
                "policy-space-name": mapping['ptg_tenant'],
                "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                        mapping['endpoint_group_name']),
                "interface-name": args['port'].port_name,
                "mac": mapping['mac_address'],
                "promiscuous-mode": mapping['promiscuous_mode'],
                "uuid": args['port'].vif_id,
                "attributes": {'vm-name': 'somename'},
                "neutron-network": "net_id",
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "ip": ['192.168.0.2', '192.168.1.2', '192.169.8.1',
                       '192.169.8.254'],
                # FIP mapping will be in the file
                "ip-address-mapping": [{
                    'uuid': '1', 'mapped-ip': '192.168.0.2',
                    'floating-ip': '172.10.0.1',
                    'endpoint-group-name': 'profile_name|nat-epg-name',
                    'policy-space-name': 'nat-epg-tenant'},
                    {'uuid': '2', 'mapped-ip': '192.168.1.2',
                     'floating-ip': '172.10.0.2'}]})

        self.agent._write_vrf_file.assert_called_once_with(
            'l3p_id', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16'])})

        self.agent._write_vrf_file.reset_mock()

        # Bind another port for the same L3P, VRF file is not written
        args = self._port_bound_args('opflex')
        args['port'].gbp_details = mapping
        self.agent.port_bound(**args)
        self.assertFalse(self.agent._write_vrf_file.called)
        self.agent._write_vrf_file.reset_mock()

        # Bind another port on a different L3P, new VRF file added
        args = self._port_bound_args('opflex')
        args['port'].gbp_details = self._get_gbp_details(l3_policy_id='newid')
        self.agent.port_bound(**args)
        self.agent._write_vrf_file.assert_called_once_with(
            'newid', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16'])})
        self.agent._write_vrf_file.reset_mock()

        # Bind another port on a same L3P, but subnets changed
        args = self._port_bound_args('opflex')
        args['port'].gbp_details = self._get_gbp_details(
            l3_policy_id='newid', vrf_subnets=['192.170.0.0/16'])
        self.agent.port_bound(**args)
        self.agent._write_vrf_file.assert_called_once_with(
            'newid', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.170.0.0/16'])})

    def test_port_unbound_delete_vrf_file(self):
        # Bind 2 ports on same VRF
        self.agent.int_br = mock.Mock()

        # Port 1
        mapping = self._get_gbp_details()
        self.agent.of_rpc.get_gbp_details.return_value = mapping
        args_1 = self._port_bound_args('opflex')
        args_1['port'].gbp_details = mapping
        self.agent.port_bound(**args_1)

        # Port 2
        args_2 = self._port_bound_args('opflex')
        args_2['port'].gbp_details = mapping
        self.agent.port_bound(**args_2)

        self.agent._delete_vrf_file.reset_mock()
        self.agent.port_unbound(args_1['port'].vif_id)
        # VRF file not deleted
        self.assertFalse(self.agent._delete_vrf_file.called)

        self.agent._delete_vrf_file.reset_mock()
        self.agent.port_unbound(args_2['port'].vif_id)
        # VRF file deleted
        self.agent._delete_vrf_file.assert_called_once_with('l3p_id')

        self.agent._write_vrf_file.reset_mock()
        # At this point, creation of a new port on that VRF will recreate the
        # file
        args_3 = self._port_bound_args('opflex')
        args_3['port'].gbp_details = mapping
        self.agent.port_bound(**args_3)
        self.agent._write_vrf_file.assert_called_once_with(
            'l3p_id', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16'])})

    def test_port_bound_no_mapping(self):
        self.agent.int_br = mock.Mock()
        self.agent.of_rpc.get_gbp_details.return_value = None
        args = self._port_bound_args('opflex')
        args['port'].gbp_details = None
        self.agent.port_bound(**args)
        self.assertFalse(self.agent.int_br.set_db_attribute.called)
        self.assertFalse(self.agent.provision_local_vlan.called)
        self.assertFalse(self.agent._write_endpoint_file.called)

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

    def test_scan_ports(self):
        fake_sub1 = {'tenant_id': 'tenant-id', 'id': 'someid'}
        fake_sub2 = {'tenant_id': 'tenant-id-2', 'id': 'someid'}
        self.agent.subnet_update(mock.Mock(), fake_sub1)
        self.agent.subnet_update(mock.Mock(), fake_sub2)
        port_info = self.agent.scan_ports(set())
        # Empty since no tenant is server by this agent ATM
        self.assertEqual(set(), port_info['vrf_updated'])
        # Update list emptied
        self.assertEqual(set(), self.agent.updated_vrf)
        self.assertEqual(set(['tenant-id', 'tenant-id-2']),
                         self.agent.backup_updated_vrf)

        # Bind port for tenant-id
        mapping = self._get_gbp_details(l3_policy_id='tenant-id')
        self.agent.of_rpc.get_gbp_details.return_value = mapping
        args = self._port_bound_args('opflex')
        args['port'].gbp_details = mapping
        self.agent.port_bound(**args)
        self.agent.subnet_update(mock.Mock(), fake_sub1)
        self.agent.subnet_update(mock.Mock(), fake_sub2)

        port_info = self.agent.scan_ports(set())
        # Port info will have tenant-id to be served
        self.assertEqual(set(['tenant-id']), port_info['vrf_updated'])
        # Update list emptied
        self.assertEqual(set(), self.agent.updated_vrf)
        self.assertEqual(set(['tenant-id', 'tenant-id-2']),
                         self.agent.backup_updated_vrf)

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
        self.agent._write_vrf_file.reset_mock()
        self.agent.subnet_update(mock.Mock(), fake_sub)

        port_info = self.agent.scan_ports(set())
        self.agent.process_network_ports(port_info, False)
        self.agent.of_rpc.get_vrf_details_list.assert_called_once_with(
            mock.ANY, mock.ANY, set(['tenant-id']), mock.ANY)
        self.agent._write_vrf_file.assert_called_once_with(
            'tenant-id', {
                "domain-policy-space": mapping['vrf_tenant'],
                "domain-name": mapping['vrf_name'],
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16',
                                            '1.1.1.0/24'])})
