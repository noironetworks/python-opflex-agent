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

from opflexagent import as_metadata_manager

TEST_TENANT = 'some_tenant'
TEST_NAME = 'some_name'
HASH_RESULT = 'a6cb6f24-92d6-31b5-21e6-25b41c0fddc1'
JSON_DATA = {"foo": "bar"}
JSON_FILE_DATA = '{"foo": "bar"}'


class TestEpWatcher(base.BaseTestCase):

    def setUp(self):
        super(TestEpWatcher, self).setUp()

    def test_hash(self):
        with mock.patch('opflexagent.as_metadata_manager.FileProcessor.run'):
            self.watcher = as_metadata_manager.EpWatcher()
            hash = self.watcher.gen_domain_uuid(TEST_TENANT, TEST_NAME)
            self.assertEqual(hash, HASH_RESULT)

    def test_read_json_file(self):
        with mock.patch('builtins.open',
                new=mock.mock_open(read_data=JSON_FILE_DATA)) as open_file:
            data = as_metadata_manager.read_jsonfile('foo')
            open_file.assert_called_once_with('foo', 'r')
            self.assertEqual(data, JSON_DATA)

    def test_write_json_file(self):
        with mock.patch('builtins.open') as open_file:
            as_metadata_manager.write_jsonfile('foo', JSON_DATA)
            open_file.assert_called_once_with('foo', 'w')
            write_list = []
            for mc in open_file.mock_calls:
                if 'write' in str(mc):
                    write_data = str(mc).split('write')[1][2:-2]
                    write_list.append(write_data)
            write_string = ''.join(write_list)
            self.assertEqual(write_string, JSON_FILE_DATA)
