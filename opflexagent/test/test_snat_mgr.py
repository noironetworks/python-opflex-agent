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
