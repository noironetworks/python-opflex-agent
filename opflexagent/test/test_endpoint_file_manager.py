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

from opflexagent import gbp_ovs_agent
from opflexagent.utils.ep_managers import endpoint_file_manager

from neutron.agent.dhcp import config as dhcp_config
from neutron.openstack.common import uuidutils
from neutron.tests import base
from oslo_config import cfg

_uuid = uuidutils.generate_uuid
EP_DIR = '.%s_endpoints/'


class TestEndpointFileManager(base.BaseTestCase):

    def setUp(self):
        cfg.CONF.register_opts(dhcp_config.DHCP_OPTS)
        super(TestEndpointFileManager, self).setUp()
        cfg.CONF.set_default('quitting_rpc_timeout', 10, 'AGENT')
        self.ep_dir = EP_DIR % _uuid()
        self.manager = self._initialize_agent()
        self.manager._write_endpoint_file = mock.Mock()
        self.manager._write_vrf_file = mock.Mock()
        self.manager._delete_endpoint_file = mock.Mock()
        self.manager._delete_vrf_file = mock.Mock()
        self.manager.snat_iptables = mock.Mock()
        self.manager.snat_iptables.setup_snat_for_es = mock.Mock(
            return_value = tuple([None, None]))
        self.manager._release_int_fip = mock.Mock()
        self.addCleanup(self._purge_endpoint_dir)

    def _check_call_list(self, expected, observed, check_all=True):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        if check_all:
            self.assertFalse(
                len(observed),
                msg='There are more calls than expected: %s' % str(observed))

    def _purge_endpoint_dir(self):
        try:
            shutil.rmtree(self.ep_dir)
        except OSError:
            pass

    def _initialize_agent(self):
        cfg.CONF.set_override('epg_mapping_dir', self.ep_dir, 'OPFLEX')
        kwargs = gbp_ovs_agent.create_agent_config_map(cfg.CONF)
        agent = endpoint_file_manager.EndpointFileManager().initialize(
            'h1', mock.Mock(), kwargs)
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
                   'app_profile_name': 'profile_name',
                   'ptg_tenant': 'apic_tenant',
                   'endpoint_group_name': 'epg_name',
                   'promiscuous_mode': False,
                   'vm-name': 'somename',
                   'extra_ips': ['192.169.8.1', '192.169.8.253',
                                 '192.169.8.254'],
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
                                    'fixed_ip_address': '192.168.1.2',
                                    'nat_epg_name': 'nat-epg-name',
                                    'nat_epg_tenant': 'nat-epg-tenant'},
                                   # FIP pointing to one extra-ip
                                   {'id': '7',
                                    'floating_ip_address': '172.10.0.7',
                                    'floating_network_id': 'ext_net',
                                    'router_id': 'ext_rout',
                                    'port_id': 'port_id',
                                    'fixed_ip_address': '192.169.8.1',
                                    'nat_epg_tenant': 'nat-epg-tenant',
                                    'nat_epg_name': 'nat-epg-name'}],
                   'ip_mapping': [{'external_segment_name': 'EXT-1',
                                   'nat_epg_tenant': 'nat-epg-tenant',
                                   'nat_epg_name': 'nat-epg-name'}],
                   'host_snat_ips': [{'external_segment_name': 'EXT-1',
                                      'host_snat_ip': '200.0.0.10',
                                      'gateway_ip': '200.0.0.1',
                                      'prefixlen': 8}],
                   'owned_addresses': ['192.168.0.2'],
                   'attestation': [{'name': 'some_name',
                                    'validator': 'base64string', 'mac': 'mac'}]
                   }
        pattern.update(**kwargs)
        return pattern

    def _port_bound_args(self):
        port = mock.Mock()
        port.vif_id = uuidutils.generate_uuid()
        port.net_uuid = 'net_uuid'
        port.fixed_ips = [{'subnet_id': 'id1', 'ip_address': '192.168.0.2'},
                          {'subnet_id': 'id2', 'ip_address': '192.168.1.2'}]
        port.device_owner = 'compute:'
        port.port_name = 'name'
        return port

    def test_port_bound(self):
        mapping = self._get_gbp_details()
        self.manager.snat_iptables.setup_snat_for_es.return_value = tuple(
            ['foo-if', 'foo-mac'])
        port = self._port_bound_args()
        self.manager.declare_endpoint(port, mapping)

        port_id = port.vif_id
        ep_name = port_id + '_' + mapping['mac_address']
        ep_file = {"policy-space-name": mapping['ptg_tenant'],
                   "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                           mapping['endpoint_group_name']),
                   "interface-name": port.port_name,
                   "mac": 'aa:bb:cc:00:11:22',
                   "promiscuous-mode": mapping['promiscuous_mode'],
                   "uuid": port.vif_id + '|aa-bb-cc-00-11-22',
                   "attributes": {'vm-name': 'somename'},
                   "neutron-network": port.net_uuid,
                   "domain-policy-space": 'apic_tenant',
                   "domain-name": 'name_of_l3p',
                   "ip": ['192.168.0.2', '192.168.1.2', '192.169.8.1',
                          '192.169.8.253', '192.169.8.254'],
                   # FIP mapping will be in the file
                   "ip-address-mapping": [
                       {'uuid': '1', 'mapped-ip': '192.168.0.2',
                        'floating-ip': '172.10.0.1',
                        'endpoint-group-name': 'profile_name|nat-epg-name',
                        'policy-space-name': 'nat-epg-tenant'},
                       {'uuid': '2', 'mapped-ip': '192.168.1.2',
                        'endpoint-group-name': 'profile_name|nat-epg-name',
                        'policy-space-name': 'nat-epg-tenant',
                        'floating-ip': '172.10.0.2'},
                       # for the extra-ip
                       {'uuid': '7', 'mapped-ip': '192.169.8.1',
                        'endpoint-group-name': 'profile_name|nat-epg-name',
                        'policy-space-name': 'nat-epg-tenant',
                        'floating-ip': '172.10.0.7'},
                       {'uuid': mock.ANY, 'mapped-ip': '192.169.8.253',
                        'floating-ip': '169.254.0.0',
                        'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                        'endpoint-group-name': 'profile_name|nat-epg-name',
                        'policy-space-name': 'nat-epg-tenant'},
                       {'uuid': mock.ANY, 'mapped-ip': '192.169.8.254',
                        'floating-ip': '169.254.0.1',
                        'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                        'endpoint-group-name': 'profile_name|nat-epg-name',
                        'policy-space-name': 'nat-epg-tenant'}],
                   "attestation": mapping['attestation']}
        snat_ep_file = {'mac': 'foo-mac', 'interface-name': 'foo-if',
                        'ip': ['200.0.0.10'],
                        'policy-space-name': 'nat-epg-tenant',
                        'attributes': mock.ANY,
                        'promiscuous-mode': True,
                        'endpoint-group-name': 'profile_name|nat-epg-name',
                        'uuid': mock.ANY}
        snat_ep_uuid = [x[0][1]['uuid']
            for x in self.manager._write_endpoint_file.call_args_list
            if x[0][0] == 'EXT-1']
        self._check_call_list(
            [mock.call(ep_name, ep_file), mock.call('EXT-1', snat_ep_file)],
            self.manager._write_endpoint_file.call_args_list)
        snat_ep_file['uuid'] = snat_ep_uuid[0] if snat_ep_uuid else None

        self.manager.snat_iptables.setup_snat_for_es.assert_called_with(
            'EXT-1', '200.0.0.10', None, '200.0.0.1/8', None, None,
            None, None)
        self.manager._write_vrf_file.assert_called_once_with(
            'l3p_id', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16',
                                            '169.254.0.0/16'])})

        # Send same port info again
        self.manager._write_vrf_file.reset_mock()
        self.manager.snat_iptables.setup_snat_for_es.reset_mock()

        self.manager.declare_endpoint(port, mapping)
        self.manager._write_endpoint_file.assert_called_with(ep_name, ep_file)
        self.assertFalse(self.manager._write_vrf_file.called)
        self.assertFalse(self.manager.snat_iptables.setup_snat_for_es.called)

        # Remove an extra-ip
        self.manager._write_vrf_file.reset_mock()
        mapping.update({'extra_ips': ['192.169.8.1', '192.169.8.253']})
        ep_file["ip"].remove('192.169.8.254')
        ep_file["ip-address-mapping"] = [x
            for x in ep_file["ip-address-mapping"]
                if x['mapped-ip'] != '192.169.8.254']

        self.manager.declare_endpoint(port, mapping)
        self.manager._write_endpoint_file.assert_called_with(ep_name, ep_file)
        self.manager._release_int_fip.assert_called_with(
            4, port_id, mapping['mac_address'], 'EXT-1', '192.169.8.254')

        # Remove SNAT external segment
        self.manager._write_vrf_file.reset_mock()
        self.manager._release_int_fip.reset_mock()
        mapping.update({'ip_mapping': []})

        ep_file["ip-address-mapping"] = [x
            for x in ep_file["ip-address-mapping"] if not x.get('next-hop-if')]
        self.manager.declare_endpoint(port, mapping)
        self.manager._write_endpoint_file.assert_called_with(ep_name, ep_file)
        self.manager._release_int_fip.assert_called_with(
            4, port_id, mapping['mac_address'], 'EXT-1')

        self.manager._write_vrf_file.reset_mock()
        self.manager.snat_iptables.setup_snat_for_es.reset_mock()

        # Bind another port for the same L3P, VRF file is not written
        port = self._port_bound_args()
        self.manager.declare_endpoint(port, mapping)
        self.assertFalse(self.manager._write_vrf_file.called)
        self.assertFalse(self.manager.snat_iptables.setup_snat_for_es.called)
        self.manager._write_vrf_file.reset_mock()

        # Bind another port on a different L3P, new VRF file added
        port = self._port_bound_args()
        mapping = self._get_gbp_details(l3_policy_id='newid')
        self.manager.declare_endpoint(port, mapping)
        self.manager._write_vrf_file.assert_called_once_with(
            'newid', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16',
                                            '169.254.0.0/16'])})
        self.manager._write_vrf_file.reset_mock()
        self.manager._write_endpoint_file.reset_mock()
        self.manager.snat_iptables.setup_snat_for_es.reset_mock()

        # Bind another port on a same L3P, but subnets changed.
        # Also change the host SNAT IP
        port = self._port_bound_args()
        mapping = self._get_gbp_details(
            l3_policy_id='newid', vrf_subnets=['192.170.0.0/16'],
            host_snat_ips=[{'external_segment_name': 'EXT-1',
                            'host_snat_ip': '200.0.0.11',
                            'gateway_ip': '200.0.0.2',
                            'prefixlen': 8}])
        snat_ep_file['ip'] = ['200.0.0.11']
        self.manager.declare_endpoint(port, mapping)
        self.manager._write_vrf_file.assert_called_once_with(
            'newid', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.170.0.0/16',
                                            '169.254.0.0/16'])})
        self._check_call_list([mock.call('EXT-1', snat_ep_file)],
            self.manager._write_endpoint_file.call_args_list,
            False)
        self.manager.snat_iptables.setup_snat_for_es.assert_called_with(
            'EXT-1', '200.0.0.11', None, '200.0.0.2/8', None, None,
            None, 'foo-mac')

    def test_port_multiple_ep_files(self):
        # Prepare AAP list
        aaps = {'allowed_address_pairs': [
            # Non active with MAC
            {'ip_address': '192.169.0.1',
             'mac_address': 'AA:AA'},
            # Active with MAC
            {'ip_address': '192.169.0.2',
             'mac_address': 'BB:BB',
             'active': True},
            # Another address for this mac (BB:BB)
            {'ip_address': '192.169.0.7',
             'mac_address': 'BB:BB',
             'active': True},
            # Non active No MAC
            {'ip_address': '192.169.0.3'},
            # Active no MAC
            {'ip_address': '192.169.0.4',
             'active': True},
            # Non active same MAC as main
            {'ip_address': '192.169.0.5',
             'mac_address': 'aa:bb:cc:00:11:22'},
            # Active same MAC as main
            {'ip_address': '192.169.0.6',
             'mac_address': 'aa:bb:cc:00:11:22',
             'active': True}]}
        # Prepare extra details for the AAPs
        extra_details = {'BB:BB': {'extra_ips': ['192.170.0.1',
                                                 '192.170.0.2'],
                                   'floating_ip': [
                                       {'id': '171',
                                        'floating_ip_address': '173.10.0.1',
                                        'floating_network_id': 'ext_net',
                                        'router_id': 'ext_rout',
                                        'port_id': 'port_id',
                                        'fixed_ip_address': '192.170.0.1',
                                        'nat_epg_tenant': 'nat-epg-tenant',
                                        'nat_epg_name': 'nat-epg-name'}],
                                   'ip_mapping': []},
                         # AA won't be here because not active
                         'aa:bb:cc:00:11:22': {
                             'extra_ips': ['192.180.0.1', '192.180.0.2'],
                             'floating_ip': [
                                 {'id': '181',
                                  'floating_ip_address': '173.11.0.1',
                                  'floating_network_id': 'ext_net',
                                  'router_id': 'ext_rout',
                                  'port_id': 'port_id',
                                  'fixed_ip_address': '192.180.0.1',
                                  'nat_epg_tenant': 'nat-epg-tenant',
                                  'nat_epg_name': 'nat-epg-name'}],
                             'ip_mapping': []}}
        aaps['extra_details'] = extra_details
        aaps['promiscuous_mode'] = True
        mapping = self._get_gbp_details(**aaps)
        # Add a floating IPs
        mapping['floating_ip'].extend([
            # For non active with MAC AA:AA
            {'id': '3', 'floating_ip_address': '172.10.0.3',
             'floating_network_id': 'ext_net',
             'router_id': 'ext_rout', 'port_id': 'port_id',
             'fixed_ip_address': '192.169.0.1',
             'nat_epg_tenant': 'nat-epg-tenant',
             'nat_epg_name': 'nat-epg-name'},
            # For active with MAC BB:BB
            {'id': '4', 'floating_ip_address': '172.10.0.4',
             'floating_network_id': 'ext_net',
             'router_id': 'ext_rout', 'port_id': 'port_id',
             'fixed_ip_address': '192.169.0.2',
             'nat_epg_tenant': 'nat-epg-tenant',
             'nat_epg_name': 'nat-epg-name'},
            # For non-active no MAC specified address
            {'id': '5', 'floating_ip_address': '172.10.0.5',
             'floating_network_id': 'ext_net',
             'router_id': 'ext_rout', 'port_id': 'port_id',
             'fixed_ip_address': '192.169.0.3',
             'nat_epg_tenant': 'nat-epg-tenant',
             'nat_epg_name': 'nat-epg-name'}])

        self.manager.snat_iptables.setup_snat_for_es.return_value = tuple(
            ['foo-if', 'foo-mac'])
        port = self._port_bound_args()
        self.manager.declare_endpoint(port, mapping)

        # Build expected calls.
        # 3 calls are expected, one for unique MAC (AA:AA, BB:BB and main)
        expected_calls = [
            # First call, the main EP file is created.
            mock.call(
                port.vif_id + '_' + mapping['mac_address'], {
                    "policy-space-name": mapping['ptg_tenant'],
                    "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                            mapping['endpoint_group_name']),
                    "interface-name": port.port_name,
                    "mac": 'aa:bb:cc:00:11:22',
                    "promiscuous-mode": True,
                    "uuid": port.vif_id + '|aa-bb-cc-00-11-22',
                    "attributes": {'vm-name': 'somename'},
                    "neutron-network": "net_uuid",
                    "domain-policy-space": 'apic_tenant',
                    "domain-name": 'name_of_l3p',
                    # Also active AAPs are set
                    "ip": ['192.168.0.2', '192.168.1.2', '192.169.0.4',
                           '192.169.0.6', '192.169.8.1', '192.169.8.253',
                           '192.169.8.254', '192.180.0.1', '192.180.0.2'],
                    # FIP mapping will be in the file except for FIP 3 and 4
                    "ip-address-mapping": [
                        {'uuid': '1', 'mapped-ip': '192.168.0.2',
                        'floating-ip': '172.10.0.1',
                        'endpoint-group-name': 'profile_name|nat-epg-name',
                        'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': '2', 'mapped-ip': '192.168.1.2',
                         'floating-ip': '172.10.0.2',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': '5', 'mapped-ip': '192.169.0.3',
                         'floating-ip': '172.10.0.5',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.169.0.4',
                         'floating-ip': mock.ANY,
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.169.0.6',
                         'floating-ip': mock.ANY,
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': '7', 'mapped-ip': '192.169.8.1',
                         'floating-ip': '172.10.0.7',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.169.8.253',
                         'floating-ip': mock.ANY,
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.169.8.254',
                         'floating-ip': mock.ANY,
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': '181', 'mapped-ip': '192.180.0.1',
                         'floating-ip': '173.11.0.1',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.180.0.2',
                         'floating-ip': mock.ANY,
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'}],
                    # Set the proper allowed address pairs (both active and non
                    # active with the main MAC address)
                    'virtual-ip': [{'ip': '192.169.0.3',
                                    'mac': 'aa:bb:cc:00:11:22'},
                                   {'ip': '192.169.0.4',
                                    'mac': 'aa:bb:cc:00:11:22'},
                                   {'ip': '192.169.0.5',
                                    'mac': 'aa:bb:cc:00:11:22'},
                                   {'ip': '192.169.0.6',
                                    'mac': 'aa:bb:cc:00:11:22'}],
                    "attestation": mapping['attestation']}),
            # Second call for MAC address BB:BB
            mock.call(
                port.vif_id + '_' + 'BB:BB', {
                    "policy-space-name": mapping['ptg_tenant'],
                    "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                            mapping['endpoint_group_name']),
                    "interface-name": port.port_name,
                    # mac is BB:BB
                    "mac": 'BB:BB',
                    "promiscuous-mode": False,
                    "uuid": port.vif_id + '|BB-BB',
                    "attributes": {'vm-name': 'somename'},
                    "neutron-network": "net_uuid",
                    "domain-policy-space": 'apic_tenant',
                    "domain-name": 'name_of_l3p',
                    # Main IP address based on active AAP
                    "ip": ['192.169.0.2', '192.169.0.7', '192.170.0.1',
                           '192.170.0.2'],
                    # Only FIP number 4 and 171 here
                    "ip-address-mapping": [
                        {'uuid': '4', 'mapped-ip': '192.169.0.2',
                         'floating-ip': '172.10.0.4',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': '171', 'mapped-ip': '192.170.0.1',
                         'floating-ip': '173.10.0.1',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'}],
                    # Set the proper allowed address pairs with MAC BB:BB
                    'virtual-ip': [{'ip': '192.169.0.2', 'mac': 'BB:BB'},
                                   {'ip': '192.169.0.7', 'mac': 'BB:BB'}],
                    "attestation": mapping['attestation']}),
            # Third call for MAC address AA:AA
            mock.call(
                port.vif_id + '_' + 'AA:AA', {
                    "policy-space-name": mapping['ptg_tenant'],
                    "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                            mapping['endpoint_group_name']),
                    "interface-name": port.port_name,
                    "promiscuous-mode": False,
                    "uuid": port.vif_id + '|AA-AA',
                    "attributes": {'vm-name': 'somename'},
                    "neutron-network": "net_uuid",
                    "domain-policy-space": 'apic_tenant',
                    "domain-name": 'name_of_l3p',
                    # No main IP address
                    # Only FIP number 3 here
                    "ip-address-mapping": [
                        {'uuid': '3', 'mapped-ip': '192.169.0.1',
                         'floating-ip': '172.10.0.3',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'}],
                    # Set the proper allowed address pairs with MAC BB:BB
                    'virtual-ip': [{'ip': '192.169.0.1', 'mac': 'AA:AA'}],
                    "attestation": mapping['attestation']}),
            # SNAT endpoint
            mock.call(
                'EXT-1', {'mac': 'foo-mac', 'interface-name': 'foo-if',
                          'ip': ['200.0.0.10'],
                          'policy-space-name': 'nat-epg-tenant',
                          'attributes': mock.ANY,
                          'promiscuous-mode': True,
                          'endpoint-group-name': 'profile_name|nat-epg-name',
                          'uuid': mock.ANY})]
        self._check_call_list(expected_calls,
                              self.manager._write_endpoint_file.call_args_list)

    def test_port_unbound_delete_vrf_file(self):
        # Bind 2 ports on same VRF

        # Port 1
        mapping = self._get_gbp_details()
        port_1 = self._port_bound_args()

        self.manager.declare_endpoint(port_1, mapping)

        # Port 2
        port_2 = self._port_bound_args()
        self.manager.declare_endpoint(port_2, mapping)

        self.manager._delete_vrf_file.reset_mock()
        self.manager.undeclare_endpoint(port_1.vif_id)
        # VRF file not deleted
        self.assertFalse(self.manager._delete_vrf_file.called)

        self.manager._delete_vrf_file.reset_mock()
        self.manager.undeclare_endpoint(port_2.vif_id)
        # VRF file deleted
        self.manager._delete_vrf_file.assert_called_once_with('l3p_id')

        self.manager._write_vrf_file.reset_mock()
        # At this point, creation of a new port on that VRF will recreate the
        # file
        port_3 = self._port_bound_args()
        self.manager.declare_endpoint(port_3, mapping)
        self.manager._write_vrf_file.assert_called_once_with(
            'l3p_id', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16',
                                            '169.254.0.0/16'])})

    def test_port_bound_no_mapping(self):
        port = self._port_bound_args()
        self.manager.declare_endpoint(port, None)
        self.assertFalse(self.manager._write_endpoint_file.called)
