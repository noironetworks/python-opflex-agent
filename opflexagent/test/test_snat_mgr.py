# Copyright (c) 2020 Cisco Systems
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

from unittest import mock

from neutron.tests import base
from oslo_config import cfg

from opflexagent import snat_iptables_manager

TEST_HASH_STRING = 'a_test_hash_string'
HASH_RESULT = 'of-dd6bf9992ab0'


class TestSnatManager(base.BaseTestCase):

    def setUp(self):
        super(TestSnatManager, self).setUp()
        self.bridge_manager = mock.Mock()
        self.mgr = snat_iptables_manager.SnatIptablesManager(
            self.bridge_manager)

    def test_hash_for_es(self):
        hash = self.mgr._get_hash_for_es(TEST_HASH_STRING)
        self.assertEqual(hash, HASH_RESULT)

    def test_setup_snat_for_es_skips_without_any_ip(self):
        with mock.patch.object(self.mgr, '_cleanup') as cleanup, \
                mock.patch.object(self.mgr, '_add_port_and_netns') as add_ns, \
                mock.patch.object(self.mgr, '_setup_routes') as setup_routes, \
                mock.patch.object(self.mgr, '_setup_iptables') as setup_ipt:
            result = self.mgr.setup_snat_for_es('EXT-1', next_hop_mac='aa:bb')

        self.assertEqual((None, 'aa:bb'), result)
        cleanup.assert_not_called()
        add_ns.assert_not_called()
        setup_routes.assert_not_called()
        setup_ipt.assert_not_called()

    def test_setup_snat_for_es_ipv4_programs_namespace_routes_iptables(self):
        fake_if_dev = mock.Mock()
        fake_if_dev.link.address = 'de:ad:be:ef:00:01'

        with mock.patch.object(self.mgr, '_get_hash_for_es',
                               return_value='of-hash-if'), \
                mock.patch.object(self.mgr, '_cleanup') as cleanup, \
                mock.patch.object(self.mgr, '_add_port_and_netns',
                                  return_value=fake_if_dev) as add_ns, \
                mock.patch.object(self.mgr, '_setup_routes') as setup_routes, \
                mock.patch.object(self.mgr, '_setup_iptables') as setup_ipt:
            result = self.mgr.setup_snat_for_es(
                'EXT-1', ip_start='10.0.0.2', ip_gw='10.0.0.1/24', mtu=1400)

        self.assertEqual(('of-hash-if', 'de:ad:be:ef:00:01'), result)
        cleanup.assert_called_once_with('of-hash-if', 'of-hash-if')
        add_ns.assert_called_once_with(
            'of-hash-if', 'of-hash-if', if_mac=None, mtu=1400)
        setup_routes.assert_called_once_with(
            fake_if_dev, 4, '10.0.0.2', '10.0.0.2', '10.0.0.1/24')
        setup_ipt.assert_called_once_with(
            'of-hash-if', 'of-hash-if', '10.0.0.2', '10.0.0.2', None, None)

    def test_cleanup_snat_all_respects_exclusions(self):
        self.bridge_manager.get_port_name_list.return_value = [
            'of-a', 'of-b', 'other-port']
        with mock.patch.object(self.mgr, '_get_hash_for_es',
                               return_value='of-b'), \
                mock.patch.object(self.mgr, '_cleanup') as cleanup:
            self.mgr.cleanup_snat_all(exclude_es=['EXT-2'])

        cleanup.assert_called_once_with('of-a', 'of-a')

    def test_check_if_exists_uses_hashed_namespace_name(self):
        ipw = mock.Mock()
        ipw.netns.exists.return_value = True
        with mock.patch.object(self.mgr, '_get_hash_for_es',
                               return_value='of-check'), \
                mock.patch(
                    'opflexagent.snat_iptables_manager.'
                    'ip_lib.IPWrapper',
                    return_value=ipw):
            exists = self.mgr.check_if_exists('EXT-1')

        self.assertTrue(exists)
        ipw.netns.exists.assert_called_once_with('of-check')

    def test_cleanup_deletes_namespace_and_conntrack_when_enabled(self):
        cfg.CONF.set_override('enable_snat_conn_track', True, 'OPFLEX')
        self.mgr.bridge_manager = mock.Mock()
        self.mgr.snat_conn_track_handler = mock.Mock()
        wrapper = mock.Mock()
        wrapper.netns.exists.return_value = True
        with mock.patch('opflexagent.snat_iptables_manager.ip_lib.IPWrapper',
                        return_value=wrapper):
            self.mgr._cleanup('if-name', 'ns-name')

        self.mgr.bridge_manager.delete_port.assert_called_once_with('if-name')
        self.mgr.snat_conn_track_handler.conn_track_del.\
            assert_called_once_with('ns-name')
        wrapper.netns.delete.assert_called_once_with('ns-name')

    def test_cleanup_skips_namespace_delete_when_missing(self):
        self.mgr.bridge_manager = mock.Mock()
        wrapper = mock.Mock()
        wrapper.netns.exists.return_value = False
        with mock.patch('opflexagent.snat_iptables_manager.ip_lib.IPWrapper',
                        return_value=wrapper):
            self.mgr._cleanup('if-name', 'ns-name')

        self.mgr.bridge_manager.delete_port.assert_called_once_with('if-name')
        wrapper.netns.delete.assert_not_called()

    def test_add_port_and_netns_configures_interface(self):
        cfg.CONF.set_override('enable_snat_conn_track', True, 'OPFLEX')
        self.mgr.bridge_manager = mock.Mock()
        self.mgr.snat_conn_track_handler = mock.Mock()
        if_dev = mock.Mock()
        if_dev.link.address = 'aa:bb:cc:dd:ee:ff'
        ns_wrapper = mock.Mock()
        wrapper = mock.Mock()
        wrapper.device.return_value = if_dev
        wrapper.netns.add.return_value = ns_wrapper
        with mock.patch('opflexagent.snat_iptables_manager.ip_lib.IPWrapper',
                        return_value=wrapper):
            result = self.mgr._add_port_and_netns(
                'if-name', 'ns-name', if_mac='aa:bb', mtu=1450)

        self.assertEqual(if_dev, result)
        self.mgr.bridge_manager.add_port.assert_called_once_with(
            'if-name', ('type', 'internal'))
        if_dev.link.set_address.assert_called_once_with('aa:bb')
        if_dev.link.set_netns.assert_called_once_with('ns-name')
        if_dev.link.set_mtu.assert_called_once_with(1450)
        if_dev.link.set_up.assert_called_once_with()
        self.mgr.snat_conn_track_handler.conn_track_create.\
            assert_called_once_with('ns-name')
        self.assertEqual(3, ns_wrapper.netns.execute.call_count)

    def test_setup_routes_adds_gateway_and_local_ranges(self):
        if_dev = mock.Mock()
        if_dev.name = 'if-name'
        self.mgr._setup_routes(
            if_dev, 4, '10.0.0.10', '10.0.0.12', '10.0.0.1/24')

        if_dev.addr.add.assert_called_once_with('10.0.0.10/24')
        if_dev.route.add_gateway.assert_called_once_with('10.0.0.1')
        self.assertTrue(if_dev.route._as_root.called)

    def test_setup_iptables_programs_ipv4_and_ipv6(self):
        iptables = mock.Mock()
        iptables.ipv4 = {}
        iptables.ipv6 = {}
        table_cls = mock.Mock(side_effect=lambda: mock.Mock())
        with mock.patch('opflexagent.snat_iptables_manager.'
                        'iptables_manager.IptablesManager',
                        return_value=iptables), \
                mock.patch('opflexagent.snat_iptables_manager.'
                           'iptables_manager.IptablesTable', table_cls):
            self.mgr._setup_iptables(
                'ns-name', 'if-name', '10.0.0.10', '10.0.0.12',
                '2001:db8::10', '2001:db8::12')

        iptables.ipv4['nat'].add_rule.assert_any_call(
            'POSTROUTING',
            '-o if-name -j SNAT --to-source 10.0.0.10-10.0.0.12',
            wrap=False)
        iptables.ipv6['filter'].add_rule.assert_any_call(
            'OUTPUT', '-p icmpv6 --icmpv6-type redirect -j DROP', wrap=False)
        iptables.apply.assert_called_once_with()

    def test_setup_snat_for_es_returns_existing_mac_without_ips(self):
        self.assertEqual(
            (None, 'aa:bb'),
            self.mgr.setup_snat_for_es('es-name', next_hop_mac='aa:bb'))

    def test_setup_snat_for_es_configures_ipv4(self):
        if_dev = mock.Mock()
        if_dev.link.address = 'aa:bb:cc:dd:ee:ff'
        with mock.patch.object(self.mgr, '_cleanup') as cleanup, \
                mock.patch.object(self.mgr, '_add_port_and_netns',
                                  return_value=if_dev) as add_netns, \
                mock.patch.object(self.mgr, '_setup_routes') as routes, \
                mock.patch.object(self.mgr, '_setup_iptables') as iptables:
            next_hop_if, next_hop_mac = self.mgr.setup_snat_for_es(
                'es-name', ip_start='10.0.0.10', ip_gw='10.0.0.1/24')

        self.assertEqual(self.mgr._get_hash_for_es('es-name'), next_hop_if)
        self.assertEqual('aa:bb:cc:dd:ee:ff', next_hop_mac)
        cleanup.assert_called_once_with(next_hop_if, next_hop_if)
        add_netns.assert_called_once_with(
            next_hop_if, next_hop_if, if_mac=None, mtu=None)
        routes.assert_called_once_with(
            if_dev, 4, '10.0.0.10', '10.0.0.10', '10.0.0.1/24')
        iptables.assert_called_once_with(
            next_hop_if, next_hop_if, '10.0.0.10', '10.0.0.10', None, None)

    def test_cleanup_snat_all_excludes_requested_ports(self):
        self.mgr.bridge_manager = mock.Mock()
        keep = self.mgr._get_hash_for_es('keep')
        delete = self.mgr._get_hash_for_es('delete')
        self.mgr.bridge_manager.get_port_name_list.return_value = [
            keep, delete, 'tap1']
        with mock.patch.object(self.mgr, '_cleanup') as cleanup:
            self.mgr.cleanup_snat_all(exclude_es=['keep'])
        cleanup.assert_called_once_with(delete, delete)

    def test_check_if_exists_uses_namespace_hash(self):
        wrapper = mock.Mock()
        wrapper.netns.exists.return_value = True
        with mock.patch('opflexagent.snat_iptables_manager.ip_lib.IPWrapper',
                        return_value=wrapper):
            self.assertTrue(self.mgr.check_if_exists('es-name'))
        wrapper.netns.exists.assert_called_once_with(
            self.mgr._get_hash_for_es('es-name'))
