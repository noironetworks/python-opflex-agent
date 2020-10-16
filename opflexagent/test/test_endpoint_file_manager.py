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

import os
import shutil
import sys

from unittest import mock
sys.modules["apicapi"] = mock.Mock()  # noqa
sys.modules["pyinotify"] = mock.Mock()  # noqa

from opflexagent import gbp_agent
from opflexagent import snat_iptables_manager
from opflexagent.test import base
from opflexagent.utils.ep_managers import endpoint_file_manager

from neutron.conf.agent import dhcp as dhcp_config
from neutron_lib import constants as n_constants
from oslo_config import cfg
from oslo_utils import uuidutils

_uuid = uuidutils.generate_uuid
EP_DIR = '.%s_endpoints/'


class TestEndpointFileManager(base.OpflexTestBase):

    def setUp(self):
        dhcp_config.register_agent_dhcp_opts(cfg.CONF)
        super(TestEndpointFileManager, self).setUp()
        cfg.CONF.set_default('quitting_rpc_timeout', 10, 'AGENT')
        self.ep_dir = EP_DIR % _uuid()
        self.manager = self._initialize_agent()
        self.manager.nat_mtu_size = 9000
        self._mock_agent(self.manager)
        self.addCleanup(self._purge_endpoint_dir)

    def _purge_endpoint_dir(self):
        try:
            shutil.rmtree(self.ep_dir)
        except OSError:
            pass

    def _initialize_agent(self):
        cfg.CONF.set_override('epg_mapping_dir', self.ep_dir, 'OPFLEX')
        kwargs = gbp_agent.create_agent_config_map(cfg.CONF)
        agent = endpoint_file_manager.EndpointFileManager().initialize(
            'h1', mock.Mock(), kwargs)
        agent.bridge_manager.get_patch_port_pair_names = (mock.Mock(
            return_value=('qpi', 'qpf')))
        return agent

    def _mock_agent(self, agent):
        agent._write_endpoint_file = mock.Mock(
            return_value=agent.epg_mapping_file)
        agent._write_vrf_file = mock.Mock()
        agent._write_lbiface_file = mock.Mock()
        agent._delete_endpoint_file = mock.Mock()
        agent._delete_vrf_file = mock.Mock()
        agent.snat_iptables = mock.Mock()
        agent.snat_iptables.setup_snat_for_es = mock.Mock(
            return_value=tuple([None, None]))

    def _port(self):
        port = mock.Mock()
        port.vif_id = uuidutils.generate_uuid()
        port.net_uuid = 'net_uuid'
        port.fixed_ips = [{'subnet_id': 'id1', 'ip_address': '192.168.0.2'},
                          {'subnet_id': 'id2', 'ip_address': '192.168.1.2'}]
        port.device_owner = 'compute:'
        port.port_name = 'tap' + port.vif_id[6:]
        port.trunk_details = None
        return port

    def test_port_bound(self):
        mapping = self._get_gbp_details()
        self.manager.snat_iptables.setup_snat_for_es.return_value = tuple(
            ['foo-if', 'foo-mac'])
        port = self._port()
        self.manager._release_int_fip = mock.Mock()
        self.manager.declare_endpoint(port, mapping)

        port_id = port.vif_id
        ep_name = port_id + '_' + mapping['mac_address']
        ep_file = {"policy-space-name": mapping['ptg_tenant'],
                   "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                           mapping['endpoint_group_name']),
                   "access-interface": port.port_name,
                   "access-uplink-interface": 'qpf',
                   "interface-name": 'qpi',
                   "mac": 'aa:bb:cc:00:11:22',
                   "promiscuous-mode": mapping['promiscuous_mode'],
                   "uuid": port.vif_id + '|aa-bb-cc-00-11-22',
                   "attributes": {'vm-name': 'somename'},
                   "neutron-network": port.net_uuid,
                   "neutron-metadata-optimization": True,
                   "domain-policy-space": 'apic_tenant',
                   "domain-name": 'name_of_l3p',
                   "ip": ['192.168.0.2', '192.168.1.2', '192.169.8.1',
                          '192.169.8.253', '192.169.8.254'],
                   "anycast-return-ip": ['192.168.0.2', '192.168.1.2'],
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
                        'attributes': {'vm-name': 'snat|h1|EXT-1'},
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
            None, None, mtu=9000)
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
        port = self._port()
        self.manager.declare_endpoint(port, mapping)
        self.assertFalse(self.manager._write_vrf_file.called)
        self.assertFalse(self.manager.snat_iptables.setup_snat_for_es.called)
        self.manager._write_vrf_file.reset_mock()

        # Bind another port on a different L3P, new VRF file added
        port = self._port()
        mapping = self._get_gbp_details(l3_policy_id='newid')
        self.manager.declare_endpoint(port, mapping)
        self.manager._write_vrf_file.assert_called_once_with(
            'newid', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16',
                                            '169.254.0.0/16'])})
        self.manager.snat_iptables.setup_snat_for_es.assert_called_with(
            'EXT-1', '200.0.0.10', None, '200.0.0.1/8', None, None,
            None, None, mtu=9000)
        self.manager._write_vrf_file.reset_mock()
        self.manager._write_endpoint_file.reset_mock()
        self.manager._write_lbiface_file.reset_mock()
        self.manager.snat_iptables.setup_snat_for_es.reset_mock()

        # Bind another port on a same L3P, but subnets changed.
        # Also change the host SNAT IP
        port = self._port()
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
            None, 'foo-mac', mtu=9000)

    def test_port_segmentation_labels(self):
        mapping = self._get_gbp_details(
            segmentation_labels=['zone = dmz', ' linux '],
            extra_ips=[],
            vrf_name='name_of_l3p',
            vrf_tenant='apic_tenant',
            vrf_subnets=['192.168.0.0/16', '192.169.0.0/16'],
            floating_ip=[],
            ip_mapping=[],
            host_snat_ips=[],
            owned_addresses=[],
            attestation=[])
        port = self._port()
        self.manager.declare_endpoint(port, mapping)

        port_id = port.vif_id
        ep_name = port_id + '_' + mapping['mac_address']
        ep_file = {"eg-mapping-alias": (mapping['ptg_tenant'] + "_" +
                                        mapping['app_profile_name'] + "_" +
                                        mapping['endpoint_group_name']),
                   "access-interface": port.port_name,
                   "access-uplink-interface": 'qpf',
                   "interface-name": 'qpi',
                   "mac": 'aa:bb:cc:00:11:22',
                   "promiscuous-mode": mapping['promiscuous_mode'],
                   "uuid": port.vif_id + '|aa-bb-cc-00-11-22',
                   "attributes": {'vm-name': 'somename', 'zone': 'dmz',
                                  'linux': ''},
                   "neutron-network": port.net_uuid,
                   "neutron-metadata-optimization": True,
                   "domain-policy-space": 'apic_tenant',
                   "domain-name": 'name_of_l3p',
                   "ip": ['192.168.0.2', '192.168.1.2'],
                   "anycast-return-ip": ['192.168.0.2', '192.168.1.2'],
                   "attestation": []}
        self.manager._write_endpoint_file.assert_called_once_with(
                ep_name, ep_file)

    def test_port_nested_domain(self):
        mapping = self._get_gbp_details(
            extra_ips=[],
            vrf_name='name_of_l3p',
            vrf_tenant='apic_tenant',
            vrf_subnets=['192.168.0.0/16', '192.169.0.0/16'],
            floating_ip=[],
            ip_mapping=[],
            host_snat_ips=[],
            owned_addresses=[],
            attestation=[],
            nested_domain_name='kubernetes',
            nested_domain_type='nested-kubernetes',
            nested_domain_infra_vlan=4093,
            nested_domain_service_vlan=1000,
            nested_domain_node_network_vlan=1001,
            nested_domain_allowed_vlans=[2, 3, 4],
            nested_host_vlan=4094,
            security_group=[{'policy-space': 'common',
                             'name': 'gbp_default'}],
            qos_policy={'policy-space': 'common',
                        'name': 'gbp_default'},)

        port = self._port()
        self.manager.declare_endpoint(port, mapping)

        port_id = port.vif_id
        ep_name = port_id + '_' + mapping['mac_address']
        ep_file = {"endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                           mapping['endpoint_group_name']),
                   "access-interface": port.port_name,
                   "access-uplink-interface": 'qpf',
                   "interface-name": 'qpi',
                   "mac": 'aa:bb:cc:00:11:22',
                   "access-interface-vlan": 4094,
                   "access-allow-untagged": True,
                   "promiscuous-mode": mapping['promiscuous_mode'],
                   "uuid": port.vif_id + '|aa-bb-cc-00-11-22',
                   "attributes": {'vm-name': 'somename'},
                   "neutron-network": port.net_uuid,
                   "neutron-metadata-optimization": True,
                   "domain-policy-space": 'apic_tenant',
                   "domain-name": 'name_of_l3p',
                   "ip": ['192.168.0.2', '192.168.1.2'],
                   "anycast-return-ip": ['192.168.0.2', '192.168.1.2'],
                   "attestation": [],
                   'policy-space-name': 'apic_tenant',
                   'security-group': [{'policy-space': 'common',
                                       'name': 'gbp_default'}],
                   'qos-policy': {'policy-space': 'common',
                                  'name': 'gbp_default'}}
        lbiface_file = {
                   "interface-name": 'qpi',
                   "uuid": mock.ANY,
                   'openstack_nested_domain_metadata': {
                           'name': 'kubernetes', 'type': 'nested-kubernetes'},
                   'trunk-vlans': [{'start': 2, 'end': 4},
                       {'start': 1000, 'end': 1001},
                       {'start': 4093}]}
        uplink_lbiface_file = {
                   "interface-name": 'patch-fab-ex',
                   "uuid": mock.ANY,
                   'openstack_nested_domain_metadata': {
                           'name': 'kubernetes', 'type': 'nested-kubernetes'},
                   'trunk-vlans': [{'start': 2, 'end': 4},
                       {'start': 1000, 'end': 1001},
                       {'start': 4093}]}
        self.manager._write_endpoint_file.assert_called_once_with(
                ep_name, ep_file)
        calls = [mock.call(ep_name, lbiface_file),
                 mock.call(ep_name + '_uplink', uplink_lbiface_file)]
        self.assertEqual(2, self.manager._write_lbiface_file.call_count)
        self.manager._write_lbiface_file.assert_has_calls(calls)

    def test_list_to_ranges(self):
        li = [1, 2, 3, 3000, 4093]
        exp_rng = [{'start': 1, 'end': 3},
                   {'start': 3000}, {'start': 4093}]
        rng = self.manager._list_to_range(li)
        self.assertEqual(exp_rng, rng)
        li = [1, 2, 3, 3000, 0, 4093, 3000]
        exp_rng = [{'start': 1, 'end': 3},
                   {'start': 3000}, {'start': 4093}]
        rng = self.manager._list_to_range(li)
        self.assertEqual(exp_rng, rng)
        li = [1, 2, 3000, 0, -2, 4093, 4094, 5000, 3000]
        exp_rng = [{'start': 1, 'end': 2},
                   {'start': 3000}, {'start': 4093}]
        rng = self.manager._list_to_range(li)
        self.assertEqual(exp_rng, rng)
        li = [3000, 1, 4093]
        exp_rng = [{'start': 1},
                   {'start': 3000}, {'start': 4093}]
        rng = self.manager._list_to_range(li)
        self.assertEqual(exp_rng, rng)

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
            # Non active CIDR
            {'ip_address': '192.169.1.0/24'},
            # Active entry in the CIDR
            {'ip_address': '192.169.1.6',
             'mac_address': 'aa:bb:cc:00:11:22',
             'active': True},
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
                                   'ip_mapping': [
                                       {'external_segment_name': 'EXT-1',
                                        'nat_epg_tenant': 'nat-epg-tenant',
                                        'nat_epg_name': 'nat-epg-name'}]},
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

        port = self._port()
        # Build expected calls.
        # 3 calls are expected, one for unique MAC (AA:AA, BB:BB and main)
        expected_calls = [
            # First call, the main EP file is created.
            mock.call(
                port.vif_id + '_' + mapping['mac_address'], {
                    "policy-space-name": mapping['ptg_tenant'],
                    "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                            mapping['endpoint_group_name']),
                    "access-interface": port.port_name,
                    "access-uplink-interface": 'qpf',
                    "interface-name": 'qpi',
                    "mac": 'aa:bb:cc:00:11:22',
                    "promiscuous-mode": True,
                    "uuid": port.vif_id + '|aa-bb-cc-00-11-22',
                    "attributes": {'vm-name': 'somename'},
                    "neutron-network": "net_uuid",
                    "neutron-metadata-optimization": True,
                    "domain-policy-space": 'apic_tenant',
                    "domain-name": 'name_of_l3p',
                    # Also active AAPs are set
                    "ip": ['192.168.0.2', '192.168.1.2', '192.169.0.4',
                           '192.169.0.6', '192.169.1.6', '192.169.8.1',
                           '192.169.8.253', '192.169.8.254', '192.180.0.1',
                           '192.180.0.2'],
                    "anycast-return-ip": ['192.168.0.2', '192.168.1.2',
                                          '192.169.0.4', '192.169.0.6',
                                          '192.169.1.6'],
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
                         'floating-ip': '169.254.0.0',
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.169.0.6',
                         'floating-ip': '169.254.0.1',
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.169.1.6',
                         'floating-ip': '169.254.0.2',
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': '7', 'mapped-ip': '192.169.8.1',
                         'floating-ip': '172.10.0.7',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.169.8.253',
                         'floating-ip': '169.254.0.3',
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.169.8.254',
                         'floating-ip': '169.254.0.4',
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': '181', 'mapped-ip': '192.180.0.1',
                         'floating-ip': '173.11.0.1',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.180.0.2',
                         'floating-ip': '169.254.0.5',
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
                                    'mac': 'aa:bb:cc:00:11:22'},
                                   {'ip': '192.169.1.0/24',
                                    'mac': 'aa:bb:cc:00:11:22'}],
                    "attestation": mapping['attestation']}),
            # Second call for MAC address BB:BB
            mock.call(
                port.vif_id + '_' + 'BB:BB', {
                    "policy-space-name": mapping['ptg_tenant'],
                    "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                            mapping['endpoint_group_name']),
                    "access-interface": port.port_name,
                    "access-uplink-interface": 'qpf',
                    "interface-name": 'qpi',
                    # mac is BB:BB
                    "mac": 'BB:BB',
                    "promiscuous-mode": False,
                    "uuid": port.vif_id + '|BB-BB',
                    "attributes": {'vm-name': 'somename'},
                    "neutron-network": "net_uuid",
                    "neutron-metadata-optimization": True,
                    "domain-policy-space": 'apic_tenant',
                    "domain-name": 'name_of_l3p',
                    # Main IP address based on active AAP
                    "ip": ['192.169.0.2', '192.169.0.7', '192.170.0.1',
                           '192.170.0.2'],
                    "anycast-return-ip": ['192.169.0.2', '192.169.0.7'],
                    # Only FIP number 4 and 171 here
                    "ip-address-mapping": [
                        {'uuid': '4', 'mapped-ip': '192.169.0.2',
                         'floating-ip': '172.10.0.4',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.169.0.7',
                         'floating-ip': '169.254.0.6',
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': '171', 'mapped-ip': '192.170.0.1',
                         'floating-ip': '173.10.0.1',
                         'endpoint-group-name': 'profile_name|nat-epg-name',
                         'policy-space-name': 'nat-epg-tenant'},
                        {'uuid': mock.ANY, 'mapped-ip': '192.170.0.2',
                         'floating-ip': '169.254.0.7',
                         'next-hop-if': 'foo-if', 'next-hop-mac': 'foo-mac',
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
                    "access-interface": port.port_name,
                    "access-uplink-interface": 'qpf',
                    "interface-name": 'qpi',
                    "promiscuous-mode": False,
                    "uuid": port.vif_id + '|AA-AA',
                    "attributes": {'vm-name': 'somename'},
                    "neutron-network": "net_uuid",
                    "neutron-metadata-optimization": True,
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
        self.manager.snat_iptables.setup_snat_for_es.return_value = tuple(
            ['foo-if', 'foo-mac'])
        self.manager._release_int_fip = mock.Mock()
        with mock.patch.object(endpoint_file_manager.EndpointFileManager,
                               '_delete_endpoint_files'):
            self.manager.declare_endpoint(port, mapping)
            self._check_call_list(
                expected_calls,
                self.manager._write_endpoint_file.call_args_list)
            self.manager._delete_endpoint_files.assert_called_once_with(
                port.vif_id,
                mac_exceptions=set(['AA:AA', 'BB:BB', 'aa:bb:cc:00:11:22']))

    def test_port_unbound_delete_vrf_file(self):
        # Bind 2 ports on same VRF

        # Port 1
        mapping = self._get_gbp_details()
        port_1 = self._port()

        self.manager.declare_endpoint(port_1, mapping)

        # Port 2
        port_2 = self._port()
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
        port_3 = self._port()
        self.manager.declare_endpoint(port_3, mapping)
        self.manager._write_vrf_file.assert_called_once_with(
            'l3p_id', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16',
                                            '169.254.0.0/16'])})

    def test_port_bound_no_mapping(self):
        port = self._port()
        self.manager.declare_endpoint(port, None)
        self.assertFalse(self.manager._write_endpoint_file.called)

    def test_delete_endpoint_files(self):
        self.manager._write_file('uuid1_AA', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid1_BB', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid1_CC', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid2_BB', {}, self.manager.epg_mapping_file)
        self.manager._delete_endpoint_files(
            'uuid1', mac_exceptions=set(['AA', 'CC']))
        ls = os.listdir(self.ep_dir)
        self.assertEqual(set(['uuid1_AA.ep', 'uuid1_CC.ep', 'uuid2_BB.ep']),
                         set(ls))

    def test_delete_ep_and_lbiface_files(self):
        self.manager.ext_seg_next_hop['uni:snat:l3out'] = 'foo_nh_info'
        self.manager._write_file('uuid1_AA', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid1_BB', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid1_BB', {},
                self.manager.lbiface_mapping_file_fmt)
        self.manager._write_file('uuid1_BB_uplink', {},
                self.manager.lbiface_mapping_file_fmt)
        self.manager._write_file('uuid1_CC', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid2_BB', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid1_uuid2_DD', {},
                self.manager.epg_mapping_file)
        self.manager._delete_endpoint_files(
            'uuid1', mac_exceptions=set(['AA', 'CC']))
        ls = os.listdir(self.ep_dir)
        self.assertEqual(set(['uuid1_AA.ep', 'uuid1_CC.ep', 'uuid2_BB.ep',
                         'uuid1_uuid2_DD.ep']), set(ls))

        self.manager._delete_endpoint_files(
            'uuid2', mac_exceptions=set(['DD']))
        ls = os.listdir(self.ep_dir)
        self.assertEqual(set(['uuid1_AA.ep', 'uuid1_CC.ep',
                         'uuid1_uuid2_DD.ep']), set(ls))

        self.manager._write_file('uni:snat:l3out', {},
            self.manager.epg_mapping_file)
        self.manager._write_file('InvalidFile', {},
            self.manager.epg_mapping_file)

        self.manager._delete_endpoint_files(
            'uuid2', mac_exceptions=set(['AA']))
        ls = os.listdir(self.ep_dir)
        self.assertEqual(set(['uuid1_AA.ep', 'uuid1_CC.ep',
                         'uni:snat:l3out.ep', 'InvalidFile.ep']),
                         set(ls))
        self.manager.ext_seg_next_hop.pop('uni:snat:l3out')

    def test_registered_endpoints(self):
        # Init directory
        self.manager._write_file('uuid1_AA', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid1_BB', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid1_CC', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid2_BB', {}, self.manager.epg_mapping_file)
        self.manager._write_file('uuid2_BB', {}, self.manager.epg_mapping_file)

        def dummy_check(self, es):
            return False

        with mock.patch.multiple(snat_iptables_manager.SnatIptablesManager,
                                 cleanup_snat_all=mock.DEFAULT,
                                 check_if_exists=dummy_check):
            manager = self._initialize_agent()
            self._mock_agent(manager)
            self.assertEqual(set(['uuid1', 'uuid2']),
                             manager.get_registered_endpoints())

            manager.undeclare_endpoint('uuid1')
            self.assertEqual(set(['uuid2']),
                             manager.get_registered_endpoints())

            mapping = self._get_gbp_details()
            port = self._port()
            manager.declare_endpoint(port, mapping)
            self.assertEqual(set(['uuid2', port.vif_id]),
                             manager.get_registered_endpoints())

    def test_existing_snat_endpoints(self):
        # Init directory
        self.manager._write_file('uuid1_AA', {}, self.manager.epg_mapping_file)
        self.manager._write_file('EXT-1', {}, self.manager.epg_mapping_file)
        self.manager._write_file('EXT-2', {}, self.manager.epg_mapping_file)
        self.manager._write_file('EXT-3', {}, self.manager.epg_mapping_file)

        def dummy_check(self, es):
            return True if es == 'EXT-2' else False

        with mock.patch.multiple(snat_iptables_manager.SnatIptablesManager,
                                 cleanup_snat_all=mock.DEFAULT,
                                 check_if_exists=dummy_check):
            manager = self._initialize_agent()
            self.assertEqual(set(['uuid1']),
                             manager.get_registered_endpoints())
            self.assertEqual(set(['EXT-1.ep', 'EXT-3.ep']),
                             manager.get_stale_endpoints())
            manager.snat_iptables.cleanup_snat_all.assert_called_once_with(
                exclude_es=['EXT-2'])

            self._mock_agent(manager)
            manager._write_endpoint_file.return_value = (
                manager.epg_mapping_file % "EXT-1")

            # declare a port that uses EXT-1
            port = self._port()
            manager.declare_endpoint(port, self._get_gbp_details())
            self.assertNotIn('EXT-1.ep', manager.get_stale_endpoints())

            # undeclaring EXT-3.ep should remove it from stale EPs
            manager.undeclare_endpoint('EXT-3.ep')
            self.assertNotIn('EXT-3.ep', manager.get_stale_endpoints())

    def test_interface_mtu(self):
        mapping = self._get_gbp_details(enable_dhcp_optimization=False,
                                        interface_mtu=0)
        port = self._port()
        self.manager._release_int_fip = mock.Mock()
        self.manager.declare_endpoint(port, mapping)
        # no MTU set whatsoever
        ep_file = None
        for arg in self.manager._write_endpoint_file.call_args_list:
            if port.vif_id in arg[0][0]:
                self.assertIsNone(ep_file)
                ep_file = arg[0][1]
        self.assertIsNotNone(ep_file)
        self.assertFalse('dhcp4' in ep_file)

        # Enable DHCP optimization
        mapping = self._get_gbp_details(enable_dhcp_optimization=True,
                                        interface_mtu=1800,
                                        subnets=[{'id': 'id1',
                                                  'enable_dhcp': True,
                                                  'ip_version': 4,
                                                  'dns_nameservers': [],
                                                  'cidr': '192.168.0.0/24',
                                                  'dhcp_server_ports': {
                                                      'fa:16:3e:a7:a3:aa': [
                                                          '192.168.0.2'
                                                      ]
                                                  },
                                                  'host_routes': []}],
                                        dhcp_lease_time=100,
                                        security_group=[
                                            {'policy-space': 'common',
                                             'name': 'gbp_default'}],
                                        qos_policy={'policy-space': 'common',
                                                    'name': 'gbp_default'},
                                        active_active_aap=True)
        port = self._port()
        self.manager._release_int_fip = mock.Mock()
        self.manager.declare_endpoint(port, mapping)
        # no MTU set whatsoever
        ep_file = None
        for arg in self.manager._write_endpoint_file.call_args_list:
            if port.vif_id in arg[0][0]:
                self.assertIsNone(ep_file)
                ep_file = arg[0][1]
        self.assertIsNotNone(ep_file)
        self.assertTrue('dhcp4' in ep_file)
        self.assertEqual(ep_file['dhcp4']['interface-mtu'], 1800)
        self.assertEqual(ep_file['dhcp4']['lease-time'], 100)
        self.assertEqual(ep_file['security-group'],
                         [{'policy-space': 'common',
                           'name': 'gbp_default'}])
        self.assertEqual(ep_file['qos-policy'],
                         {'policy-space': 'common',
                          'name': 'gbp_default'})
        self.assertTrue(ep_file['active-active-aap'])

    def test_dns_domain(self):
        cfg.CONF.set_override('dns_domain', 'my_domain')
        with mock.patch.object(snat_iptables_manager.SnatIptablesManager,
                               'cleanup_snat_all'):
            manager = self._initialize_agent()
            self._mock_agent(manager)
            mapping = self._get_gbp_details(enable_dhcp_optimization=True,
                                            interface_mtu=1800,
                                            subnets=[{'id': 'id1',
                                                      'enable_dhcp': True,
                                                      'ip_version': 4,
                                                      'dns_nameservers': [],
                                                      'cidr': '192.168.0.0/24',
                                                      'host_routes': []}],
                                            dhcp_lease_time=100)
            port = self._port()
            manager._release_int_fip = mock.Mock()
            manager.declare_endpoint(port, mapping)
            # no MTU set whatsoever
            ep_file = None
            for arg in manager._write_endpoint_file.call_args_list:
                if port.vif_id in arg[0][0]:
                    self.assertIsNone(ep_file)
                    ep_file = arg[0][1]
            self.assertIsNotNone(ep_file)
            self.assertTrue('dhcp4' in ep_file)
            self.assertEqual(ep_file['dhcp4']['domain'], 'my_domain')

            mapping = self._get_gbp_details(enable_dhcp_optimization=True,
                                            interface_mtu=1800,
                                            subnets=[{'id': 'id1',
                                                      'enable_dhcp': True,
                                                      'ip_version': 4,
                                                      'dns_nameservers': [],
                                                      'cidr': '192.168.0.0/24',
                                                      'host_routes': []}],
                                            dhcp_lease_time=100,
                                            dns_domain='my_domain2')
            port = self._port()
            manager._release_int_fip = mock.Mock()
            manager.declare_endpoint(port, mapping)
            # no MTU set whatsoever
            ep_file = None
            for arg in manager._write_endpoint_file.call_args_list:
                if port.vif_id in arg[0][0]:
                    self.assertIsNone(ep_file)
                    ep_file = arg[0][1]
            self.assertIsNotNone(ep_file)
            self.assertTrue('dhcp4' in ep_file)
            self.assertEqual(ep_file['dhcp4']['domain'], 'my_domain2')

    def _test_snat_next_hop_info(self, es_name, mapping_info, expected):
        mapping = self._get_gbp_details()
        for es in mapping['ip_mapping']:
            if es['external_segment_name'] == es_name:
                es.update(mapping_info)
        self.manager._write_endpoint_file.reset_mock()
        port = self._port()
        self.manager.declare_endpoint(port, mapping)

        snat_ep_file = [c[0][1]
            for c in self.manager._write_endpoint_file.call_args_list
            if c[0][0] == es_name]
        self.assertEqual(1, len(snat_ep_file))
        snat_ep_file = snat_ep_file[0]

        for k, v in expected.items():
            self.assertEqual(v, snat_ep_file[k])

        self.manager.undeclare_endpoint(port.vif_id)

    def test_snat_next_hop_epg(self):
        self.manager.snat_iptables.setup_snat_for_es.return_value = tuple(
            ['foo-if', 'foo-mac'])
        self.manager._release_int_fip = mock.Mock()

        self._test_snat_next_hop_info('EXT-1',
            {'next_hop_ep_epg': 'foo'},
            {'policy-space-name': 'nat-epg-tenant',
             'endpoint-group-name': 'profile_name|foo'})

        self._test_snat_next_hop_info('EXT-1',
            {'next_hop_ep_tenant': 'other'},
            {'policy-space-name': 'other',
             'endpoint-group-name': 'profile_name|nat-epg-name'})

        self._test_snat_next_hop_info('EXT-1',
            {'next_hop_ep_epg': 'foo', 'next_hop_ep_app_profile': 'lab'},
            {'policy-space-name': 'nat-epg-tenant',
             'endpoint-group-name': 'lab|foo'})

    def test_endpoint_vrf_change(self):
        mapping = self._get_gbp_details()
        port_1 = self._port()
        port_2 = self._port()

        self.manager.declare_endpoint(port_1, mapping)
        self.assertEqual('l3p_id', self.manager.vif_to_vrf[port_1.vif_id])
        self.assertEqual(set([port_1.vif_id]),
                         self.manager.vrf_dict['l3p_id']['vifs'])

        self.manager.declare_endpoint(port_2, mapping)
        self.assertEqual('l3p_id', self.manager.vif_to_vrf[port_2.vif_id])
        self.assertEqual(set([port_1.vif_id, port_2.vif_id]),
                         self.manager.vrf_dict['l3p_id']['vifs'])

        # no VRF change
        self.manager._write_vrf_file.reset_mock()
        self.manager.declare_endpoint(port_1, mapping)
        self.manager._write_vrf_file.assert_not_called()
        self.manager._delete_vrf_file.assert_not_called()
        self.assertEqual('l3p_id', self.manager.vif_to_vrf[port_1.vif_id])
        self.assertEqual(set([port_1.vif_id, port_2.vif_id]),
                         self.manager.vrf_dict['l3p_id']['vifs'])

        # port_1 VRF changes to 'l3p_id_1'
        mapping['l3_policy_id'] = 'l3p_id_1'
        self.manager.declare_endpoint(port_1, mapping)
        self.manager._delete_vrf_file.assert_not_called()
        self.manager._write_vrf_file.assert_called_once_with(
            'l3p_id_1', {
                "domain-policy-space": 'apic_tenant',
                "domain-name": 'name_of_l3p',
                "internal-subnets": sorted(['192.168.0.0/16',
                                            '192.169.0.0/16',
                                            '169.254.0.0/16'])})
        self.assertEqual('l3p_id_1', self.manager.vif_to_vrf[port_1.vif_id])
        self.assertEqual('l3p_id', self.manager.vif_to_vrf[port_2.vif_id])
        self.assertEqual(set([port_1.vif_id]),
                         self.manager.vrf_dict['l3p_id_1']['vifs'])
        self.assertEqual(set([port_2.vif_id]),
                         self.manager.vrf_dict['l3p_id']['vifs'])

        # port_2 VRF changes to 'l3p_id_1'
        self.manager._write_vrf_file.reset_mock()
        self.manager.declare_endpoint(port_2, mapping)
        self.manager._delete_vrf_file.assert_called_once_with('l3p_id')
        self.manager._write_vrf_file.assert_not_called()
        self.assertEqual('l3p_id_1', self.manager.vif_to_vrf[port_1.vif_id])
        self.assertEqual('l3p_id_1', self.manager.vif_to_vrf[port_2.vif_id])
        self.assertEqual(set([port_1.vif_id, port_2.vif_id]),
                         self.manager.vrf_dict['l3p_id_1']['vifs'])

    def test_port_snat_info_reset(self):
        write_ep = self.manager._write_endpoint_file

        mapping = self._get_gbp_details(floating_ip=[])
        port_1 = self._port()
        self.manager.declare_endpoint(port_1, mapping)

        self.assertTrue('EXT-1' in
                        [x[0][0] for x in write_ep.call_args_list])

        self.manager.undeclare_endpoint(port_1.vif_id)

        write_ep.reset_mock()
        mapping['host_snat_ips'] = []
        self.manager.declare_endpoint(port_1, mapping)

        self.assertFalse('EXT-1' in
                         [x[0][0] for x in write_ep.call_args_list])

    def test_v6_subnets(self):
        # Enable DHCP optimization
        V6_DNS = '2001:db8:1::10'
        mapping = self._get_gbp_details(enable_dhcp_optimization=True,
                                        interface_mtu=1800,
                                        subnets=[{'id': 'id1',
                                                  'enable_dhcp': True,
                                                  'ip_version': 6,
                                                  'dns_nameservers': [V6_DNS],
                                                  'cidr': '2001:db8::/64',
                                                  'host_routes': []}],
                                        dhcp_lease_time=100)
        port = self._port()
        self.manager._release_int_fip = mock.Mock()
        self.manager.declare_endpoint(port, mapping)
        # no MTU set whatsoever
        ep_file = None
        for arg in self.manager._write_endpoint_file.call_args_list:
            if port.vif_id in arg[0][0]:
                self.assertIsNone(ep_file)
                ep_file = arg[0][1]
        self.assertIsNotNone(ep_file)
        self.assertTrue('dhcp6' in ep_file)
        self.assertEqual(ep_file['dhcp6']['interface-mtu'], 1800)
        self.assertEqual(ep_file['dhcp6']['dns-servers'], [V6_DNS])

    def test_port_trunk_details(self):
        mapping = self._get_gbp_details()
        self.manager.snat_iptables.setup_snat_for_es.return_value = tuple(
            ['foo-if', 'foo-mac'])
        port = self._port()
        trunk_details = {
            'trunk_id': 'some_id',
            'master_port_id': port.vif_id,
            'subports': [{
                'port_id': 'sub1',
                'segmentation_type': 'vlan',
                'segmentation_id': 100,
            }, {
                'port_id': 'sub2',
                'segmentation_type': 'vlan',
                'segmentation_id': 101,
            }]
        }
        port.trunk_details = trunk_details
        self.manager._release_int_fip = mock.Mock()
        self.manager.declare_endpoint(port, mapping)

        master_port_id = port.vif_id
        master_port_name = port.port_name
        ep_name = master_port_id + '_' + mapping['mac_address']
        ep_file = {"policy-space-name": mapping['ptg_tenant'],
                   "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                           mapping['endpoint_group_name']),
                   "access-interface": master_port_name,
                   "access-uplink-interface": 'qpf',
                   "interface-name": 'qpi',
                   "mac": 'aa:bb:cc:00:11:22',
                   "promiscuous-mode": mapping['promiscuous_mode'],
                   "uuid": port.vif_id + '|aa-bb-cc-00-11-22',
                   "attributes": {'vm-name': 'somename'},
                   "neutron-network": port.net_uuid,
                   "neutron-metadata-optimization": True,
                   "domain-policy-space": 'apic_tenant',
                   "domain-name": 'name_of_l3p',
                   "ip": ['192.168.0.2', '192.168.1.2', '192.169.8.1',
                          '192.169.8.253', '192.169.8.254'],
                   "anycast-return-ip": ['192.168.0.2', '192.168.1.2'],
                   # FIP mapping will be in the file
                   "ip-address-mapping": mock.ANY,
                   "attestation": mapping['attestation']}
        snat_ep_file = {'mac': 'foo-mac', 'interface-name': 'foo-if',
                        'ip': ['200.0.0.10'],
                        'policy-space-name': 'nat-epg-tenant',
                        'attributes': {'vm-name': 'snat|h1|EXT-1'},
                        'promiscuous-mode': True,
                        'endpoint-group-name': 'profile_name|nat-epg-name',
                        'uuid': mock.ANY}
        self._check_call_list(
            [mock.call(ep_name, ep_file), mock.call('EXT-1', snat_ep_file)],
            self.manager._write_endpoint_file.call_args_list)

        self.manager._write_endpoint_file.reset_mock()
        port.vif_id = 'sub1'
        ep_file['uuid'] = port.vif_id + '|aa-bb-cc-00-11-22'
        ep_name = master_port_id + '_sub1_' + mapping['mac_address']
        ep_file['access-interface-vlan'] = 100
        old_method = self.manager.bridge_manager.get_port_vif_name

        def get_port_vif_name(vif_id):
            return 'tap' + vif_id[6:]
        self.manager.bridge_manager.get_port_vif_name = get_port_vif_name
        self.manager.declare_endpoint(port, mapping)
        self.manager._write_endpoint_file.assert_called_with(ep_name, ep_file)
        self.manager.bridge_manager.get_port_vif_name = old_method

    def test_bad_mapping(self):
        mapping = self._get_gbp_details()
        port_1 = self._port()

        # Get rid of the EPG, verify we don't get an exception
        mapping['endpoint_group_name'] = None
        self.manager.declare_endpoint(port_1, mapping)

    def _test_vlan_net_port_bound(self, svi=False):
        # the SVI related info we expect to see
        # on get_gbp_details
        port = self._port()
        vlan_info = {}
        if svi:
            vlan_info['svi'] = True
        vlan_info['endpoint_group_name'] = 'svi-net-id'
        vlan_info['enable_dhcp_optimization'] = True
        vlan_info['subnets'] = [{'id': 'id1',
                                 'enable_dhcp': True,
                                 'ip_version': 4,
                                 'dns_nameservers': [],
                                 'cidr': '192.168.0.0/24',
                                 'host_routes': []}]
        mapping = self._get_gbp_details(**vlan_info)
        port.segmentation_id = 1234
        port.network_type = 'vlan'
        self.manager.declare_endpoint(port, mapping)
        epargs = self.manager._write_endpoint_file.call_args_list
        self.assertEqual(True, epargs[1][0][1].get('provider-vlan'))
        self.assertEqual(port.segmentation_id,
            epargs[1][0][1].get('ext-encap-id'))
        if vlan_info.get('svi'):
            self.assertEqual(vlan_info['endpoint_group_name'],
                epargs[1][0][1].get('endpoint-group-name'))
        else:
            self.assertEqual((mapping['app_profile_name'] + '|' +
                vlan_info['endpoint_group_name']),
                epargs[1][0][1].get('endpoint-group-name'))

        self.assertEqual(False,
            epargs[1][0][1].get('neutron-metadata-optimization'))
        self.assertIsNone(epargs[1][0][1].get('dhcp4'))

    def test_vlan_net_no_svi_port_bound(self):
        self._test_vlan_net_port_bound()

    def test_vlan_net_svi_port_bound(self):
        self._test_vlan_net_port_bound(svi=True)

    def _test_dhcp_ep(self, svi=False):

        port = self._port()
        port.device_owner = n_constants.DEVICE_OWNER_DHCP

        vlan_info = {}
        if svi:
            vlan_info['svi'] = True
        vlan_info['endpoint_group_name'] = 'svi-net-id'
        vlan_info['subnets'] = [{'id': 'id1',
                                 'enable_dhcp': True,
                                 'ip_version': 4,
                                 'dns_nameservers': [],
                                 'cidr': '192.168.0.0/24',
                                 'host_routes': []}]
        mapping = self._get_gbp_details(**vlan_info)
        mapping.pop('vm-name')

        self.manager.declare_endpoint(port, mapping)
        epargs = self.manager._write_endpoint_file.call_args_list
        if svi:
            self.assertEqual(('dhcp' + '|' +
                vlan_info['endpoint_group_name']),
                epargs[1][0][1].get('attributes').get('vm-name'))
        else:
            self.assertEqual(('dhcp' + '|' +
                mapping['ptg_tenant'] + '|' +
                mapping['app_profile_name'] + '|' +
                vlan_info['endpoint_group_name']),
                epargs[1][0][1].get('attributes').get('vm-name'))

    def test_dhcp_ep_svi(self):
        self._test_dhcp_ep(svi=True)

    def test_dhcp_ep_no_svi(self):
        self._test_dhcp_ep()

    def test_snat_to_fip(self):
        """Test mapping between host snat ips to floating ips."""
        self.manager.snat_iptables.setup_snat_for_es.return_value = tuple(
            ['foo-if', 'foo-mac'])
        mapping = self._get_gbp_details(floating_ip=[])
        port_1 = self._port()
        self.manager.declare_endpoint(port_1, mapping)

        mapping['host_snat_ips'] = []
        mapping = self._get_gbp_details(host_snat_ips=[],
            ip_mapping=[],
            floating_ip=[{'id': '2',
                          'floating_ip_address': '172.10.0.2',
                          'floating_network_id': 'ext_net',
                          'router_id': 'ext_rout',
                          'port_id': 'port_id',
                          'fixed_ip_address': '192.168.0.2',
                          'nat_epg_name': 'EXT-1',
                          'nat_epg_tenant': 'nat-epg-tenant'}])
        self.manager.declare_endpoint(port_1, mapping)
