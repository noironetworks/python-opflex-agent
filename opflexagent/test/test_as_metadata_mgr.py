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

import copy
import sys

from unittest import mock

from neutron.tests import base

from opflexagent import as_metadata_manager

TEST_TENANT = 'some_tenant'
TEST_NAME = 'some_name'
HASH_RESULT = 'a6cb6f24-92d6-31b5-21e6-25b41c0fddc1'
JSON_DATA = {"foo": "bar"}
JSON_FILE_DATA = '{"foo": "bar"}'

if sys.version_info.major == 2:
    MOCK_MODULE = '__builtin__.open'
else:
    MOCK_MODULE = 'builtins.open'

curr_alloc_json = {
    "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9": {
        "domain-name": "sauto_k8s-bm-1_l3out-1_vrf",
        "domain-policy-space": "common",
        "next-hop-ip": "169.254.240.3",
        "uuid": "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9"
    },
    "99e788f5-f579-83d2-6b9f-3051a21f63ab": {
        "domain-name": "k8s-bm-1_UnroutedVRF",
        "domain-policy-space": "common",
        "next-hop-ip": "169.254.240.4",
        "uuid": "99e788f5-f579-83d2-6b9f-3051a21f63ab"
    }
}
onefile_curr_alloc_json = {
    "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9": {
        "domain-name": "sauto_k8s-bm-1_l3out-1_vrf",
        "domain-policy-space": "common",
        "next-hop-ip": "169.254.240.3",
        "uuid": "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9"
    }
}
nochange_fileA = {
    "uuid": "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9",
    "interface-name": "of-svc-ovsport",
    "service-mac": "02:6a:66:eb:26:6a",
    "domain-policy-space": "common",
    "domain-name": "sauto_k8s-bm-1_l3out-1_vrf",
    "service-mapping": [
        {
            "service-ip": "169.254.169.254",
            "gateway-ip": "169.254.1.1",
            "next-hop-ip": "169.254.240.3"
        }
    ]
}
change_fileA = {
    "uuid": "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9",
    "interface-name": "of-svc-ovsport",
    "service-mac": "02:6a:66:eb:26:6a",
    "domain-policy-space": "other",
    "domain-name": "wrong_domain_name",
    "service-mapping": [
        {
            "service-ip": "169.254.169.254",
            "gateway-ip": "169.254.1.1",
            "next-hop-ip": "169.254.240.3"
        }
    ]
}
nochange_fileB = {
    "uuid": "99e788f5-f579-83d2-6b9f-3051a21f63ab",
    "interface-name": "of-svc-ovsport",
    "service-mac": "02:6a:66:eb:26:6a",
    "domain-policy-space": "common",
    "domain-name": "k8s-bm-1_UnroutedVRF",
    "service-mapping": [
        {
            "service-ip": "169.254.169.254",
            "gateway-ip": "169.254.1.1",
            "next-hop-ip": "169.254.240.4"
        }
    ]
}

class TestEpWatcher(base.BaseTestCase):

    def setUp(self):
        super(TestEpWatcher, self).setUp()

    def test_hash(self):
        with mock.patch('opflexagent.as_metadata_manager.FileProcessor.run'):
            self.watcher = as_metadata_manager.EpWatcher()
            hash = self.watcher.gen_domain_uuid(TEST_TENANT, TEST_NAME)
            self.assertEqual(hash, HASH_RESULT)

    def test_read_json_file(self):
        with mock.patch(MOCK_MODULE,
                new=mock.mock_open(read_data=JSON_FILE_DATA)) as open_file:
            data = as_metadata_manager.read_jsonfile('foo')
            open_file.assert_called_once_with('foo', 'r')
            self.assertEqual(data, JSON_DATA)

    def test_write_json_file(self):
        with mock.patch(MOCK_MODULE) as open_file:
            as_metadata_manager.write_jsonfile('foo', JSON_DATA)
            open_file.assert_called_once_with('foo', 'w')
            write_list = []
            for mc in open_file.mock_calls:
                if 'write' in str(mc):
                    write_data = str(mc).split('write')[1][2:-2]
                    write_list.append(write_data)
            write_string = ''.join(write_list)
            self.assertEqual(write_string, JSON_FILE_DATA)


class TestStateWatcher(base.BaseTestCase):

    def setUp(self):
        super(TestStateWatcher, self).setUp()

    @mock.patch('opflexagent.as_metadata_manager.write_jsonfile')
    @mock.patch('os.remove')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager'
                '.update_supervisor')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.del_ip')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.add_ip')
    @mock.patch('opflexagent.as_metadata_manager.FileProcessor.run')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager'
                '.get_asport_mac',
                return_value="ff-ff-ff-ff-ff-ff")
    @mock.patch('opflexagent.as_metadata_manager.read_jsonfile',
                side_effect=[copy.deepcopy(curr_alloc_json),
                             copy.deepcopy(nochange_fileA),
                             copy.deepcopy(nochange_fileB)])
    @mock.patch('os.listdir',
                return_value=["44f67ef0-1fd8-7a7e-2bfb-e650cee859a9.as",
                              "99e788f5-f579-83d2-6b9f-3051a21f63ab.as"])
    def test_process_no_change(self, listdir_patch, read_jsonfile_patch,
                               asport_mac_patch, fileprocessor_run_patch,
                               add_ip_patch, del_ip_patch, update_sv_patch,
                               os_remove_patch, write_jsonfile_patch):
        watcher = as_metadata_manager.StateWatcher()
        watcher.disable_proxy = True
        watcher.process("test")
        self.assertFalse(write_jsonfile_patch.called)
        self.assertEqual(read_jsonfile_patch.call_count, 3)
        self.assertFalse(add_ip_patch.called)
        self.assertFalse(del_ip_patch.called)
        self.assertFalse(os_remove_patch.called)

    @mock.patch('opflexagent.as_metadata_manager.write_jsonfile')
    @mock.patch('os.remove')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager'
                '.update_supervisor')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.del_ip')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.add_ip')
    @mock.patch('opflexagent.as_metadata_manager.FileProcessor.run')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager'
                '.get_asport_mac',
                return_value="ff-ff-ff-ff-ff-ff")
    @mock.patch('opflexagent.as_metadata_manager.read_jsonfile',
                side_effect=[copy.deepcopy(curr_alloc_json),
                             copy.deepcopy(change_fileA),
                             copy.deepcopy(nochange_fileB)])
    @mock.patch('os.listdir',
                return_value=["44f67ef0-1fd8-7a7e-2bfb-e650cee859a9.as",
                              "99e788f5-f579-83d2-6b9f-3051a21f63ab.as"])
    def test_process_outdated_file(self, listdir_patch, read_jsonfile_patch,
                               asport_mac_patch, fileprocessor_run_patch,
                               add_ip_patch, del_ip_patch, update_sv_patch,
                               os_remove_patch, write_jsonfile_patch):
        watcher = as_metadata_manager.StateWatcher()
        watcher.disable_proxy = True
        watcher.process("test")
        self.assertEqual(write_jsonfile_patch.call_count, 1)
        self.assertEqual(read_jsonfile_patch.call_count, 3)
        self.assertEqual(os_remove_patch.call_count, 2)
        self.assertEqual(add_ip_patch.call_count, 1)

    @mock.patch('opflexagent.as_metadata_manager.write_jsonfile')
    @mock.patch('os.remove')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager'
                '.update_supervisor')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.del_ip')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.add_ip')
    @mock.patch('opflexagent.as_metadata_manager.FileProcessor.run')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager'
                '.get_asport_mac',
                return_value="ff-ff-ff-ff-ff-ff")
    @mock.patch('opflexagent.as_metadata_manager.read_jsonfile',
                side_effect=[copy.deepcopy(curr_alloc_json),
                             copy.deepcopy(nochange_fileA),
                             copy.deepcopy(nochange_fileB)])
    @mock.patch('os.listdir',
                return_value=["44f67ef0-1fd8-7a7e-2bfb-e650cee859a9.as"])
    def test_process_create_file(self, listdir_patch, read_jsonfile_patch,
                               asport_mac_patch, fileprocessor_run_patch,
                               add_ip_patch, del_ip_patch, update_sv_patch,
                               os_remove_patch, write_jsonfile_patch):
        watcher = as_metadata_manager.StateWatcher()
        watcher.disable_proxy = True
        watcher.process("test")
        self.assertEqual(write_jsonfile_patch.call_count, 1)
        self.assertEqual(read_jsonfile_patch.call_count, 2)
        self.assertEqual(add_ip_patch.call_count, 1)
        self.assertFalse(os_remove_patch.called)
        self.assertFalse(del_ip_patch.called)

    @mock.patch('opflexagent.as_metadata_manager.write_jsonfile')
    @mock.patch('os.remove')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager'
                '.update_supervisor')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.del_ip')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.add_ip')
    @mock.patch('opflexagent.as_metadata_manager.FileProcessor.run')
    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager'
                '.get_asport_mac',
                return_value="ff-ff-ff-ff-ff-ff")
    @mock.patch('opflexagent.as_metadata_manager.read_jsonfile',
                side_effect=[copy.deepcopy(onefile_curr_alloc_json),
                             copy.deepcopy(nochange_fileA),
                             copy.deepcopy(nochange_fileB)])
    @mock.patch('os.listdir',
                return_value=["44f67ef0-1fd8-7a7e-2bfb-e650cee859a9.as",
                              "99e788f5-f579-83d2-6b9f-3051a21f63ab.as"])
    def test_process_delete_file(self, listdir_patch, read_jsonfile_patch,
                               asport_mac_patch, fileprocessor_run_patch,
                               add_ip_patch, del_ip_patch, update_sv_patch,
                               os_remove_patch, write_jsonfile_patch):
        watcher = as_metadata_manager.StateWatcher()
        watcher.disable_proxy = True
        watcher.process("test")
        self.assertEqual(os_remove_patch.call_count, 2)
        self.assertEqual(read_jsonfile_patch.call_count, 3)