# Copyright (c) 2026 Cisco Systems
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

import json
import os
import shutil

from oslo_utils import uuidutils

from opflexagent import distributed_snat_manager
from opflexagent.test import base


class TestDistributedSnatManager(base.OpflexTestBase):

    def setUp(self):
        super(TestDistributedSnatManager, self).setUp()
        self.tmp_root = '.%s_dist_snat/' % uuidutils.generate_uuid()
        self.addCleanup(self._cleanup)

        def _write(uuid, mapping_dict, file_format):
            filename = file_format % uuid
            directory = os.path.dirname(filename)
            if not os.path.exists(directory):
                os.makedirs(directory)
            with open(filename, 'w') as f:
                json.dump(mapping_dict, f)
            return filename

        def _delete(uuid, file_format):
            try:
                os.remove(file_format % uuid)
            except OSError:
                pass

        self._write = _write
        self._delete = _delete
        self.mgr = self._new_manager()

    def _new_manager(self, zone_min=None, zone_max=None):
        return distributed_snat_manager.DistributedSnatManager(
            os.path.join(self.tmp_root, 'snats'),
            os.path.join(self.tmp_root, 'service'),
            self._write,
            self._delete,
            zone_min=zone_min,
            zone_max=zone_max)

    def _cleanup(self):
        try:
            shutil.rmtree(self.tmp_root)
        except OSError:
            pass

    def _dist_snat_mapping(self, host_snat_ips=None):
        host_snat_ips = host_snat_ips or [{
            'external_segment_name': 'EXT-DIST',
            'host_snat_ip': '200.0.0.50',
            'host_snat_mac': 'aa:bb:cc:00:11:55',
            'service_mac': 'aa:bb:cc:00:22:66',
            'service_vlan': 10,
            'start_port': 10000,
            'end_port': 10999,
            'service_ip': '10.99.0.1',
            'service_vrf': 'vrf-svc',
            'dest_prefix': '0.0.0.0/0',
        }]
        return {
            'host_snat_ips': host_snat_ips,
            'vrf_tenant': 'apic_tenant',
            'vrf_name': 'name_of_l3p',
        }

    def test_sync_endpoint_writes_files_and_ep_uuid_refs(self):
        ep_mapping = {}
        dist_entry = {
            'uuid': '00000000-0000-0000-0000-ffff980a0114',
            'snat_ip': '66.66.66.7',
            'start': 100,
            'end': 199,
            'snat_file': {
                'uuid': '00000000-0000-0000-0000-ffff980a0114',
                'snat-ip': '66.66.66.7',
                'port-range': [{'start': 100, 'end': 199}]},
            'service_file': {
                'uuid': '00000000-0000-0000-0000-ffff980a0115',
                'interface-ip': '16.5.168.7'}
        }

        old_service_file = os.path.join(
            self.tmp_root, 'service',
            '00000000-0000-0000-0000-ffff980a0114.service')
        if not os.path.exists(os.path.dirname(old_service_file)):
            os.makedirs(os.path.dirname(old_service_file))
        with open(old_service_file, 'w') as f:
            json.dump({'uuid': dist_entry['uuid']}, f)

        self.mgr.sync_endpoint('port-id|aa-bb-cc-dd-ee-ff',
                               [dist_entry],
                               ep_mapping)

        self.assertEqual(['00000000-0000-0000-0000-ffff980a0114'],
                         ep_mapping.get('snat-uuids'))
        self.assertEqual(
            {'66.66.66.7': {'start': 100, 'end': 199}},
            self.mgr.get_dist_snat_mappings())

        snat_file = os.path.join(self.tmp_root, 'snats',
                                 '00000000-0000-0000-0000-ffff980a0114.snat')
        service_file = os.path.join(
            self.tmp_root, 'service',
            '00000000-0000-0000-0000-ffff980a0115.service')
        self.assertTrue(os.path.exists(snat_file))
        self.assertTrue(os.path.exists(service_file))
        self.assertFalse(os.path.exists(old_service_file))

    def test_cleanup_port_deletes_files_when_last_endpoint_removed(self):
        dist_entry = {
            'uuid': '00000000-0000-0000-0000-ffff980a0114',
            'snat_ip': '66.66.66.7',
            'start': 100,
            'end': 199,
            'snat_file': {'uuid': '00000000-0000-0000-0000-ffff980a0114'},
            'service_file': {'uuid': '00000000-0000-0000-0000-ffff980a0114'}
        }

        self.mgr.sync_endpoint('port-id|aa', [dist_entry], {})
        self.mgr.sync_endpoint('port-id-2|bb', [dist_entry], {})

        self.mgr.cleanup_port('port-id')
        # still referenced by port-id-2
        self.assertNotEqual({}, self.mgr.get_dist_snat_mappings())

        self.mgr.cleanup_port('port-id-2')
        self.assertEqual({}, self.mgr.get_dist_snat_mappings())

    def test_build_dist_snat_entries_from_host_snat_ips(self):
        mapping = {
            'host_snat_ips': [{
                'external_segment_name': (
                    'uni:tn-common:out-fab2021_2:instP-fab2021_2'),
                'host_snat_ip': '200.0.0.50',
                'host_snat_mac': 'aa:bb:cc:00:11:55',
                'service_mac': 'aa:bb:cc:00:22:66',
                'start_port': 10000,
                'end_port': 10999,
                'service_ip': '10.99.0.1',
                'service_vrf': 'vrf-svc',
                'service_vlan': 10,
                'dest_prefix': '0.0.0.0/0',
                'service_nodes': [{
                    'mac': 'dd:ee:ff:00:11:22',
                    'start_port': 20000,
                    'end_port': 20999,
                }],
            }],
            'vrf_tenant': 'apic_tenant',
            'vrf_name': 'name_of_l3p',
        }
        mapping_dict = {'interface-name': 'qpi'}

        entries = self.mgr.build_dist_snat_entries(mapping, mapping_dict)

        self.assertEqual(1, len(entries))
        entry = entries[0]
        self.assertEqual('200.0.0.50', entry['snat_ip'])
        self.assertEqual(10000, entry['start'])
        self.assertEqual(10999, entry['end'])
        self.assertEqual('patch-fab-ex',
                         entry['snat_file']['interface-name'])
        self.assertEqual('200.0.0.50', entry['snat_file']['snat-ip'])
        self.assertEqual(10, entry['snat_file']['interface-vlan'])
        self.assertEqual('aa:bb:cc:00:22:66',
                         entry['snat_file']['interface-mac'])
        self.assertEqual([{'start': 10000, 'end': 10999}],
                         entry['snat_file']['port-range'])
        self.assertEqual('common',
                         entry['service_file']['domain-policy-space'])
        self.assertEqual('vrf-svc', entry['service_file']['domain-name'])
        self.assertEqual(10, entry['service_file']['interface-vlan'])
        self.assertEqual('10.99.0.1', entry['service_file']['interface-ip'])
        self.assertEqual(1000, entry['snat_file']['zone'])
        self.assertEqual(entry['uuid'], entry['snat_file']['uuid'])
        self.assertNotEqual(entry['snat_file']['uuid'],
                            entry['service_file']['uuid'])

        new_entries = self.mgr.build_dist_snat_entries(mapping, mapping_dict)
        self.assertEqual(entry['snat_file']['uuid'],
                         new_entries[0]['snat_file']['uuid'])
        self.assertEqual(entry['service_file']['uuid'],
                         new_entries[0]['service_file']['uuid'])

    def test_build_dist_snat_entries_uses_rpc_snat_uuid(self):
        requested_snat_uuid = '11111111-2222-3333-4444-555555555555'
        mapping = {
            'host_snat_ips': [{
                'external_segment_name': 'EXT-DIST',
                'host_snat_ip': '200.0.0.50',
                'host_snat_mac': 'aa:bb:cc:00:11:55',
                'service_mac': 'aa:bb:cc:00:22:66',
                'service_vlan': 10,
                'start_port': 10000,
                'end_port': 10999,
                'service_ip': '10.99.0.1',
                'service_vrf': 'vrf-svc',
                'service_vlan': 10,
                'snat_uuid': requested_snat_uuid,
            }],
            'vrf_tenant': 'apic_tenant',
            'vrf_name': 'name_of_l3p',
        }

        entries = self.mgr.build_dist_snat_entries(
            mapping, {'interface-name': 'qpi'})

        self.assertEqual(requested_snat_uuid, entries[0]['uuid'])
        self.assertEqual(requested_snat_uuid, entries[0]['snat_file']['uuid'])

    def test_sync_endpoint_preserves_service_file_when_snat_uuid_changes(self):
        requested_snat_uuid = '11111111-2222-3333-4444-555555555555'
        endpoint_uuid = 'port-id|aa-bb-cc-dd-ee-ff'
        mapping = {
            'host_snat_ips': [{
                'external_segment_name': 'EXT-DIST',
                'host_snat_ip': '200.0.0.50',
                'host_snat_mac': 'aa:bb:cc:00:11:55',
                'service_mac': 'aa:bb:cc:00:22:66',
                'service_vlan': 10,
                'start_port': 10000,
                'end_port': 10999,
                'service_ip': '10.99.0.1',
                'service_vrf': 'vrf-svc',
                'service_vlan': 10,
            }],
            'vrf_tenant': 'apic_tenant',
            'vrf_name': 'name_of_l3p',
        }
        mapping_dict = {'interface-name': 'qpi'}

        generated_entries = self.mgr.build_dist_snat_entries(
            mapping, mapping_dict)
        generated_snat_uuid = generated_entries[0]['uuid']
        service_uuid = generated_entries[0]['service_file']['uuid']
        self.mgr.sync_endpoint(endpoint_uuid, generated_entries, {})

        mapping['host_snat_ips'][0]['snat_uuid'] = requested_snat_uuid
        requested_entries = self.mgr.build_dist_snat_entries(
            mapping, mapping_dict)
        self.assertEqual(service_uuid,
                         requested_entries[0]['service_file']['uuid'])

        self.mgr.sync_endpoint(endpoint_uuid, requested_entries, {})

        generated_snat_file = os.path.join(
            self.tmp_root, 'snats', '%s.snat' % generated_snat_uuid)
        requested_snat_file = os.path.join(
            self.tmp_root, 'snats', '%s.snat' % requested_snat_uuid)
        service_file = os.path.join(
            self.tmp_root, 'service', '%s.service' % service_uuid)
        self.assertFalse(os.path.exists(generated_snat_file))
        self.assertTrue(os.path.exists(requested_snat_file))
        self.assertTrue(os.path.exists(service_file))

    def test_build_dist_snat_entries_uses_non_common_external_segment_tenant(
            self):
        mapping = {
            'host_snat_ips': [{
                'external_segment_name': (
                    'uni:tn-snat_tenant:out-ext:instP-ext'),
                'host_snat_ip': '200.0.0.51',
                'host_snat_mac': 'aa:bb:cc:00:11:55',
                'service_vlan': 10,
                'start_port': 11000,
                'end_port': 11999,
                'service_ip': '10.99.0.2',
            }],
            'vrf_tenant': 'apic_tenant',
            'vrf_name': 'name_of_l3p',
        }
        mapping_dict = {'interface-name': 'qpi'}

        entries = self.mgr.build_dist_snat_entries(mapping, mapping_dict)

        self.assertEqual(1, len(entries))
        self.assertEqual(
            'snat_tenant',
            entries[0]['service_file']['domain-policy-space'])

    def test_build_dist_snat_entries_assigns_unique_zone_per_snat_ip(self):
        mapping = self._dist_snat_mapping([
            {
                'external_segment_name': 'EXT-DIST',
                'host_snat_ip': '200.0.0.50',
                'host_snat_mac': 'aa:bb:cc:00:11:55',
                'service_vlan': 10,
                'start_port': 10000,
                'end_port': 10999,
                'service_ip': '10.99.0.1',
            },
            {
                'external_segment_name': 'EXT-DIST',
                'host_snat_ip': '200.0.0.51',
                'host_snat_mac': 'aa:bb:cc:00:11:56',
                'service_vlan': 10,
                'start_port': 11000,
                'end_port': 11999,
                'service_ip': '10.99.0.2',
            },
        ])

        entries = self.mgr.build_dist_snat_entries(
            mapping, {'interface-name': 'qpi'})

        zones = [x['snat_file']['zone'] for x in entries]
        self.assertEqual([1000, 1001], zones)

    def test_build_dist_snat_entries_reuses_zone_from_snat_file(self):
        mapping = self._dist_snat_mapping()
        mapping_dict = {'interface-name': 'qpi'}
        entries = self.mgr.build_dist_snat_entries(mapping, mapping_dict)
        self.mgr.sync_endpoint('port-id|aa-bb-cc-dd-ee-ff', entries, {})

        restarted_mgr = self._new_manager()

        restarted_entries = restarted_mgr.build_dist_snat_entries(
            mapping, mapping_dict)

        self.assertEqual(entries[0]['snat_file']['zone'],
                         restarted_entries[0]['snat_file']['zone'])

    def test_build_dist_snat_entries_reuses_zone_after_cleanup(self):
        mapping1 = self._dist_snat_mapping([{
            'external_segment_name': 'EXT-DIST',
            'host_snat_ip': '200.0.0.50',
            'host_snat_mac': 'aa:bb:cc:00:11:55',
            'service_vlan': 10,
            'start_port': 10000,
            'end_port': 10999,
            'service_ip': '10.99.0.1',
        }])
        mapping2 = self._dist_snat_mapping([{
            'external_segment_name': 'EXT-DIST',
            'host_snat_ip': '200.0.0.51',
            'host_snat_mac': 'aa:bb:cc:00:11:56',
            'service_vlan': 10,
            'start_port': 11000,
            'end_port': 11999,
            'service_ip': '10.99.0.2',
        }])
        mapping_dict = {'interface-name': 'qpi'}

        first_entries = self.mgr.build_dist_snat_entries(mapping1,
                                                         mapping_dict)
        self.assertEqual(1000, first_entries[0]['snat_file']['zone'])
        self.mgr.sync_endpoint('port-id|aa-bb-cc-dd-ee-ff',
                               first_entries, {})
        self.mgr.sync_endpoint('port-id|aa-bb-cc-dd-ee-ff', [], {})

        second_entries = self.mgr.build_dist_snat_entries(mapping2,
                                                          mapping_dict)
        self.assertEqual(1000, second_entries[0]['snat_file']['zone'])

    def test_build_dist_snat_entries_uses_configured_zone_range(self):
        self.mgr = self._new_manager(zone_min=4000, zone_max=4002)

        mapping = self._dist_snat_mapping([
            {
                'external_segment_name': 'EXT-DIST',
                'host_snat_ip': '200.0.0.50',
                'host_snat_mac': 'aa:bb:cc:00:11:55',
                'service_vlan': 10,
                'start_port': 10000,
                'end_port': 10999,
                'service_ip': '10.99.0.1',
            },
            {
                'external_segment_name': 'EXT-DIST',
                'host_snat_ip': '200.0.0.51',
                'host_snat_mac': 'aa:bb:cc:00:11:56',
                'service_vlan': 10,
                'start_port': 11000,
                'end_port': 11999,
                'service_ip': '10.99.0.2',
            },
        ])

        entries = self.mgr.build_dist_snat_entries(
            mapping, {'interface-name': 'qpi'})

        zones = [x['snat_file']['zone'] for x in entries]
        self.assertEqual([4000, 4001], zones)

    def test_build_dist_snat_entries_uses_configured_interface(self):
        self.mgr.distributed_snat_interface = 'dist-snat-if'
        mapping = {
            'host_snat_ips': [{
                'external_segment_name': 'EXT-DIST',
                'host_snat_ip': '200.0.0.50',
                'host_snat_mac': 'aa:bb:cc:00:11:55',
                'service_vlan': 10,
                'start_port': 10000,
                'end_port': 10999,
                'service_ip': '10.99.0.1',
                'service_vrf': 'vrf-svc',
            }],
            'vrf_tenant': 'apic_tenant',
            'vrf_name': 'name_of_l3p',
        }
        mapping_dict = {'interface-name': 'qpi'}

        entries = self.mgr.build_dist_snat_entries(mapping, mapping_dict)

        self.assertEqual(1, len(entries))
        entry = entries[0]
        self.assertEqual('dist-snat-if',
                         entry['snat_file']['interface-name'])
        self.assertEqual('dist-snat-if',
                         entry['service_file']['interface-name'])
