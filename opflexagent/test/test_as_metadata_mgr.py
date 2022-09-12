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

import sys

import mock

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


class TestAsMetadataManager(base.BaseTestCase):

    def setUp(self):
        super(TestAsMetadataManager, self).setUp()
        self.mgr = as_metadata_manager.AsMetadataManager(
            as_metadata_manager.LOG, None)

    def test_add_default_route(self):
        with mock.patch('neutron.agent.linux.ip_lib.add_ip_route') as add_mock:
            self.mgr.add_default_route('1.2.3.4')
            add_mock.assert_called_once_with('of-svc', None, device=None,
                via='1.2.3.4', table='default', metric=None, scope='global')

    @mock.patch('neutron.privileged.agent.linux.ip_lib.get_ip_addresses',
        return_value=[])
    def test_has_ip(self, p_get_ip_addresses_mock):
        result = self.mgr.has_ip('1.2.3.4')
        self.assertEqual(result, False)

    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.has_ip',
    return_value=False)
    def test_add_ip(self, has_ip_mock):
        mock_path = 'neutron.agent.linux.ip_lib.add_ip_address'
        with mock.patch(mock_path) as add_ip_addr_mock:
            self.mgr.add_ip('1.2.3.4')
            add_ip_addr_mock.assert_called_once_with('1.2.3.4/%s' %
                (as_metadata_manager.SVC_IP_CIDR),
                as_metadata_manager.SVC_NS_PORT,
                as_metadata_manager.SVC_NS, 'global', True)

    @mock.patch('opflexagent.as_metadata_manager.AsMetadataManager.has_ip',
    return_value=True)
    def test_del_ip(self, has_ip_mock):
        mock_path = 'neutron.agent.linux.ip_lib.delete_ip_address'
        with mock.patch(mock_path) as check_out:
            self.mgr.del_ip('1.2.3.4')
            check_out.assert_called_once_with('1.2.3.4/%s' %
                (as_metadata_manager.SVC_IP_CIDR),
                as_metadata_manager.SVC_NS_PORT,
                as_metadata_manager.SVC_NS)

    def test_get_asport_mac(self):
        self.mgr.get_asport_mac()

    @mock.patch('neutron.agent.linux.ip_lib.IPWrapper.ensure_namespace')
    @mock.patch('neutron.privileged.agent.linux.ip_lib.create_netns')
    @mock.patch('neutron.privileged.agent.linux.ip_lib.list_netns')
    @mock.patch('neutron.privileged.agent.linux.ip_lib.create_interface')
    @mock.patch('neutron.privileged.agent.linux.ip_lib.set_link_attribute')
    @mock.patch('neutron.privileged.agent.linux.ip_lib.interface_exists',
        side_effect=[False, True])
    @mock.patch('neutron.privileged.agent.linux.ip_lib.add_ip_address')
    @mock.patch('neutron.privileged.agent.linux.ip_lib.add_ip_route')
    @mock.patch('neutron.privileged.agent.linux.ip_lib.get_ip_addresses',
        return_value=[])
    @mock.patch('neutron.agent.common.utils.execute',
        return_value=('', ''))
    def test_init_host(self, execute_patch, p_get_ip_addresses_patch,
            p_add_ip_route_patch, p_add_ip_addr_route,
            p_interface_exists_path, p_set_link_attribute_patch,
            p_create_interface_patch, p_list_netns_patch, p_create_netns_patch,
            ensure_namespace_patch):
        self.mgr.init_host()
