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
import os
import sys

from unittest import mock

from neutron.tests import base
from six.moves import queue as Queue

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
        "next-hop-ipv6": "fd00::a9fe:f003",
        "uuid": "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9"
    },
    "99e788f5-f579-83d2-6b9f-3051a21f63ab": {
        "domain-name": "k8s-bm-1_UnroutedVRF",
        "domain-policy-space": "common",
        "next-hop-ip": "169.254.240.4",
        "next-hop-ipv6": "fd00::a9fe:f004",
        "uuid": "99e788f5-f579-83d2-6b9f-3051a21f63ab"
    }
}
onefile_curr_alloc_json = {
    "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9": {
        "domain-name": "sauto_k8s-bm-1_l3out-1_vrf",
        "domain-policy-space": "common",
        "next-hop-ip": "169.254.240.3",
        "next-hop-ipv6": "fd00::a9fe:f003",
        "uuid": "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9"
    }
}
legacy_curr_alloc_json = {
    "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9": {
        "domain-name": "sauto_k8s-bm-1_l3out-1_vrf",
        "domain-policy-space": "common",
        "next-hop-ip": "169.254.240.3",
        "next-hop-ipv6": "fe80::a9fe:f003",
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
        },
        {
            "service-ip": "fe80::a9fe:a9fe",
            "gateway-ip": "fd00::a9fe:101",
            "next-hop-ip": "fd00::a9fe:f003"
        }
    ]
}
legacy_link_local_fileA = {
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
        },
        {
            "service-ip": "fe80::a9fe:a9fe",
            "gateway-ip": "fe80::a9fe:101",
            "next-hop-ip": "fe80::a9fe:f003"
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
        },
        {
            "service-ip": "fe80::a9fe:a9fe",
            "gateway-ip": "fd00::a9fe:101",
            "next-hop-ip": "fd00::a9fe:f003"
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
        },
        {
            "service-ip": "fe80::a9fe:a9fe",
            "gateway-ip": "fd00::a9fe:101",
            "next-hop-ip": "fd00::a9fe:f004"
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

    @mock.patch('opflexagent.as_metadata_manager.write_jsonfile')
    @mock.patch('opflexagent.as_metadata_manager.read_jsonfile')
    @mock.patch('os.listdir', return_value=['test.ep'])
    def test_process_writes_instance_networks_before_services(
            self, listdir_patch, read_jsonfile_patch, write_jsonfile_patch):
        watcher = as_metadata_manager.EpWatcher.__new__(
            as_metadata_manager.EpWatcher)
        watcher.svcfile = '/state/anycast_services.state'
        watcher.netsfile = '/state/instance_networks.state'

        ep_file = {
            'neutron-metadata-optimization': True,
            'domain-name': TEST_NAME,
            'domain-policy-space': TEST_TENANT,
            'neutron-network': 'net_uuid',
            'anycast-return-ip': ['fe80::f816:3eff:fe77:364b'],
        }
        read_jsonfile_patch.side_effect = [{}, ep_file]

        watcher.process('test')

        domain_uuid = watcher.gen_domain_uuid(TEST_TENANT, TEST_NAME)
        self.assertEqual(
            [
                mock.call(
                    watcher.netsfile,
                    {domain_uuid: {
                        'fe80::f816:3eff:fe77:364b': 'net_uuid'}}),
                mock.call(
                    watcher.svcfile,
                    {domain_uuid: {
                        'domain-name': TEST_NAME,
                        'domain-policy-space': TEST_TENANT,
                        'next-hop-ip': '169.254.240.3',
                        'next-hop-ipv6': 'fd00::a9fe:f003',
                        'uuid': domain_uuid}}),
            ],
            write_jsonfile_patch.call_args_list)

    @mock.patch('opflexagent.as_metadata_manager.write_jsonfile')
    @mock.patch('opflexagent.as_metadata_manager.read_jsonfile')
    @mock.patch('os.listdir',
                return_value=['project-a.ep', 'project-b.ep'])
    def test_process_scopes_common_unrouted_vrf_by_policy_space(
            self, listdir_patch, read_jsonfile_patch, write_jsonfile_patch):
        watcher = as_metadata_manager.EpWatcher.__new__(
            as_metadata_manager.EpWatcher)
        watcher.svcfile = '/state/anycast_services.state'
        watcher.netsfile = '/state/instance_networks.state'

        project_a_ep = {
            'neutron-metadata-optimization': True,
            'policy-space-name': 'project-a',
            'domain-name': 'UnroutedVRF',
            'domain-policy-space': 'common',
            'neutron-network': 'net-a',
            'anycast-return-ip': ['192.0.2.10'],
        }
        project_b_ep = {
            'neutron-metadata-optimization': True,
            'policy-space-name': 'project-b',
            'domain-name': 'UnroutedVRF',
            'domain-policy-space': 'common',
            'neutron-network': 'net-b',
            'anycast-return-ip': ['192.0.2.10'],
        }
        read_jsonfile_patch.side_effect = [{}, project_a_ep, project_b_ep]

        watcher.process('test')

        project_a_uuid = '1b9267cc-f428-22b3-4d49-24a60079ff47'
        project_b_uuid = 'd3a6c673-a3a5-6d41-c83a-e04564b6905b'
        self.assertEqual(
            [
                mock.call(
                    watcher.netsfile,
                    {
                        project_a_uuid: {'192.0.2.10': 'net-a'},
                        project_b_uuid: {'192.0.2.10': 'net-b'},
                    }),
                mock.call(
                    watcher.svcfile,
                    {
                        project_a_uuid: {
                            'domain-name': 'UnroutedVRF',
                            'domain-policy-space': 'common',
                            'next-hop-ip': '169.254.240.3',
                            'next-hop-ipv6': 'fd00::a9fe:f003',
                            'uuid': project_a_uuid},
                        project_b_uuid: {
                            'domain-name': 'UnroutedVRF',
                            'domain-policy-space': 'common',
                            'next-hop-ip': '169.254.240.4',
                            'next-hop-ipv6': 'fd00::a9fe:f004',
                            'uuid': project_b_uuid},
                    }),
            ],
            write_jsonfile_patch.call_args_list)


class TestAsMetadataManager(base.BaseTestCase):

    def setUp(self):
        super(TestAsMetadataManager, self).setUp()

    @mock.patch('os.remove')
    @mock.patch('os.listdir')
    def test_clean_files_preserves_state_files(self, listdir_patch,
                                               remove_patch):
        mgr = as_metadata_manager.AsMetadataManager.__new__(
            as_metadata_manager.AsMetadataManager)
        listdir_patch.side_effect = [
            [],
            ['anycast_services.state', 'instance_networks.state',
             'old.proxy.state'],
            [],
            [],
        ]

        mgr.clean_files()

        remove_patch.assert_called_once_with(
            '%s/old.proxy.state' % as_metadata_manager.MD_DIR)

    def test_address_pool_and_metadata_helpers(self):
        pool = as_metadata_manager.AddressPool(5, 2)
        self.assertEqual(5, pool.get_addr())
        self.assertEqual(6, pool.get_addr())
        self.assertIsNone(pool.get_addr())

        self.assertEqual('fd00::a9fe:f003',
                         as_metadata_manager.normalize_ipv6_next_hop(
                             'fe80::a9fe:f003'))
        self.assertEqual('10.0.0.1',
                         as_metadata_manager.normalize_ipv6_next_hop(
                             '10.0.0.1'))

    @mock.patch('opflexagent.as_metadata_manager.open',
                new_callable=mock.mock_open)
    def test_write_file_and_sh(self, mock_file):
        mgr = as_metadata_manager.AsMetadataManager.__new__(
            as_metadata_manager.AsMetadataManager)
        mgr.name = 'mgr'
        mgr.root_helper = None

        mgr.write_file('/tmp/test.txt', 'hello')
        mock_file.assert_called_once_with('/tmp/test.txt', 'w')

        with mock.patch(
            'opflexagent.as_metadata_manager.subprocess.check_output',
            return_value=b'ok') as check_output:
            self.assertEqual('ok', mgr.sh('echo ok'))
            check_output.assert_called_once()

        with mock.patch(
            'opflexagent.as_metadata_manager.subprocess.check_output',
            side_effect=RuntimeError('boom')):
            self.assertEqual('', mgr.sh('echo fail'))


class TestMetadataManagerLifecycleCoverage(base.BaseTestCase):

    def test_file_processor_run_and_conn_track(self):
        eventq = mock.Mock()
        eventq.get.side_effect = [
            mock.Mock(maskname='IN_DELETE', pathname='/tmp/a.ep'),
            mock.Mock(maskname='IN_CLOSE_WRITE', pathname='/tmp/b.ep'),
            as_metadata_manager.EOQ,
        ]
        eventq.get_nowait.side_effect = [
            mock.Mock(maskname='IN_MOVED_TO', pathname='/tmp/c.ep'),
            Queue.Empty,
        ]
        proc = as_metadata_manager.FileProcessor(
            '/tmp', ['.ep'], eventq, lambda files: files)
        proc.run()

        handler = as_metadata_manager.EventHandler(
            watcher=mock.Mock(), extensions=['.ep'])
        event = mock.Mock(pathname='/tmp/keep.ep', maskname='IN_CLOSE_WRITE')
        self.assertTrue(handler.action(event))

        conn = as_metadata_manager.SnatConnTrackHandler.__new__(
            as_metadata_manager.SnatConnTrackHandler)
        conn.mgr = mock.Mock()
        conn.syslog_facility = 'local0'
        conn.syslog_severity = 'notice'
        with mock.patch('opflexagent.as_metadata_manager.open',
                        new_callable=mock.mock_open()) as open_file, \
                mock.patch(
                    'opflexagent.as_metadata_manager.os.remove') as remove:
            conn.conn_track_create('netns1')
            conn.conn_track_del('netns1')
            self.assertTrue(open_file.called)
            self.assertTrue(remove.called)
        self.assertIn('opflex-conn-track-netns1', conn.conn_track_config(
            'netns1'))

        with mock.patch('opflexagent.as_metadata_manager.os.path.exists',
                        return_value=True), \
                mock.patch('opflexagent.as_metadata_manager.os.listdir',
                           return_value=['foo.snat', 'bar.txt']), \
                mock.patch.object(as_metadata_manager.SnatConnTrackHandler,
                                  'conn_track_del') as del_fn:
            conn.cleanup_all_conn_track()
            del_fn.assert_called_once_with('foo')

    def test_as_metadata_manager_lifecycle_and_helpers(self):
        mgr = as_metadata_manager.AsMetadataManager.__new__(
            as_metadata_manager.AsMetadataManager)
        mgr.root_helper = None
        mgr.name = 'mgr'
        mgr.md_filename = '/tmp/metadata.conf'
        mgr.bridge_manager = mock.Mock()
        mgr.initialized = False
        mgr.disable_proxy = False

        mgr.clean_files = mock.Mock()
        mgr.init_all = mock.Mock()
        mgr.ensure_initialized()
        self.assertTrue(mgr.initialized)

        mgr.initialized = True
        mgr.clean_files = mock.Mock()
        mgr.stop_supervisor = mock.Mock()
        mgr.ensure_terminated()
        self.assertFalse(mgr.initialized)

        mgr.sh = mock.Mock(return_value='')
        mgr.add_default_route('169.254.1.1')
        mgr.sh.assert_any_call('ip netns exec %s ip route add default via %s' %
                               (as_metadata_manager.SVC_NS,
                                '169.254.1.1'))

        mgr.sh.reset_mock()
        mgr.sh.side_effect = ['net 169.254.1.2/16', 'net 169.254.1.2/16', '']
        self.assertTrue(mgr.has_ip('169.254.1.2'))
        self.assertFalse(mgr.has_ip('169.254.1.3'))

        mgr.sh.reset_mock()
        mgr.sh.side_effect = [
            'net 169.254.1.2/16', '', 'net 169.254.1.2/16', '']
        mgr.add_ip('169.254.1.2')
        mgr.del_ip('169.254.1.2')
        self.assertEqual(2, mgr.sh.call_count)

        mgr.sh.reset_mock()
        mgr.sh.side_effect = None
        mgr.sh.return_value = 'link/ether aa:bb:cc:dd:ee:ff'
        self.assertEqual('link/ether aa:bb:cc:dd:ee:ff', mgr.get_asport_mac())

        mgr.sh.reset_mock()
        mgr.sh.side_effect = lambda *args, **kwargs: ''
        mgr.add_ip = mock.Mock()
        mgr.add_default_route = mock.Mock()
        mgr.init_host()
        mgr.bridge_manager.plug_metadata_port.assert_called_once_with(
            mgr.sh, as_metadata_manager.SVC_OVS_PORT)
        mgr.add_default_route = (
            as_metadata_manager.AsMetadataManager.add_default_route.__get__(
                mgr, as_metadata_manager.AsMetadataManager))

        mgr.write_file = mock.Mock()
        mgr.init_supervisor()
        self.assertTrue(mgr.write_file.called)
        mgr.write_file.reset_mock()

        mgr.disable_proxy = True
        mgr.init_supervisor()
        self.assertTrue(mgr.write_file.called)

        mgr.sh.reset_mock()
        mgr.sh.return_value = ''
        mgr.update_supervisor()
        self.assertEqual(2, mgr.sh.call_count)

        mgr.sh.reset_mock()
        mgr.reload_supervisor()
        self.assertEqual(1, mgr.sh.call_count)

        mgr.sh.reset_mock()
        mgr.sh.side_effect = None
        mgr.sh.return_value = 'net fe80::a9fe:f003/64'
        self.assertTrue(mgr.has_ip('fe80::a9fe:f003'))

        mgr.sh.reset_mock()
        mgr.sh.return_value = ''
        mgr.add_default_route('fd00::a9fe:101', ip_version=6)
        self.assertIn('ip -6 route add default via fd00::a9fe:101',
                  mgr.sh.call_args[0][0])

        mgr.sh.reset_mock()
        mgr.sh.return_value = 'net 169.254.1.2/16'
        self.assertTrue(mgr.has_ip('169.254.1.2'))


class TestStateWatcher(base.BaseTestCase):

    def setUp(self):
        super(TestStateWatcher, self).setUp()
        real_isfile = os.path.isfile
        netsfile = "%s/%s" % (as_metadata_manager.MD_DIR,
                              as_metadata_manager.STATE_FILENAME_NETS)

        def isfile(path):
            if path == netsfile:
                return True
            return real_isfile(path)

        self.isfile_patch = mock.patch('os.path.isfile', side_effect=isfile)
        self.isfile_mock = self.isfile_patch.start()
        self.addCleanup(self.isfile_patch.stop)

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
    @mock.patch('opflexagent.as_metadata_manager.read_jsonfile')
    @mock.patch('os.listdir')
    def test_process_waits_for_instance_networks_state(
            self, listdir_patch, read_jsonfile_patch, asport_mac_patch,
            fileprocessor_run_patch, add_ip_patch, del_ip_patch,
            update_sv_patch, os_remove_patch, write_jsonfile_patch):
        watcher = as_metadata_manager.StateWatcher()
        self.isfile_mock.side_effect = None
        self.isfile_mock.return_value = False
        watcher.process("test")

        self.assertFalse(read_jsonfile_patch.called)
        self.assertFalse(listdir_patch.called)
        self.assertFalse(write_jsonfile_patch.called)
        self.assertFalse(add_ip_patch.called)
        self.assertFalse(del_ip_patch.called)
        self.assertFalse(update_sv_patch.called)
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
        self.assertEqual(add_ip_patch.call_count, 2)

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
                             copy.deepcopy(legacy_link_local_fileA),
                             copy.deepcopy(nochange_fileB)])
    @mock.patch('os.listdir',
                return_value=["44f67ef0-1fd8-7a7e-2bfb-e650cee859a9.as",
                              "99e788f5-f579-83d2-6b9f-3051a21f63ab.as"])
    def test_process_legacy_link_local_file(self, listdir_patch,
                                            read_jsonfile_patch,
                                            asport_mac_patch,
                                            fileprocessor_run_patch,
                                            add_ip_patch, del_ip_patch,
                                            update_sv_patch,
                                            os_remove_patch,
                                            write_jsonfile_patch):
        with mock.patch(MOCK_MODULE,
                        new=mock.mock_open()) as open_file, mock.patch(
                            'opflexagent.as_metadata_manager'
                            '.AsMetadataManager.sh'):
            watcher = as_metadata_manager.StateWatcher()
            watcher.disable_proxy = False
            watcher.process("test")
        self.assertEqual(write_jsonfile_patch.call_count, 1)
        self.assertEqual(read_jsonfile_patch.call_count, 3)
        self.assertEqual(os_remove_patch.call_count, 2)
        self.assertEqual(del_ip_patch.call_count, 2)
        self.assertEqual(add_ip_patch.call_count, 2)
        self.assertEqual(update_sv_patch.call_count, 1)
        proxy = ''.join(call[0][0]
                        for call in open_file().write.call_args_list)
        self.assertIn("--metadata_host fd00::a9fe:f003 --metadata_port=80",
                      proxy)
        self.assertNotIn("--metadata_host fe80::a9fe:f003", proxy)

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
        self.assertEqual(add_ip_patch.call_count, 2)
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
        self.assertEqual(del_ip_patch.call_count, 2)

    def test_proxyconfig_dual_stack(self):
        watcher = as_metadata_manager.StateWatcher.__new__(
            as_metadata_manager.StateWatcher)
        proxy = watcher.proxyconfig(curr_alloc_json[
            "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9"])
        self.assertIn(
            "opflex-ns-proxy-44f67ef0-1fd8-7a7e-2bfb-e650cee859a9-v4", proxy)
        self.assertIn(
            "opflex-ns-proxy-44f67ef0-1fd8-7a7e-2bfb-e650cee859a9-v6", proxy)
        self.assertIn("--metadata_host 169.254.240.3 --metadata_port=80",
                      proxy)


class TestMetadataManagerCoverage(base.BaseTestCase):

    def test_file_processor_and_file_watcher_helpers(self):
        proc = as_metadata_manager.FileProcessor(
            '/tmp', ['.ep'], mock.Mock(), mock.Mock(return_value=['ok']))
        self.assertEqual(['ok'], proc.scanfiles([('update', 'x.ep'),
                                                ('delete', 'ignore.txt')]))

        watcher = as_metadata_manager.FileWatcher.__new__(
            as_metadata_manager.FileWatcher)
        watcher.name = 'watcher-test'
        watcher.watchdir = '/tmp'
        watcher.extensions = ['.ep']
        watcher.eventq = mock.Mock()
        watcher.processor = mock.Mock()
        watcher.processor.is_alive.return_value = False
        watcher.auto_restart_fileprocessor = True
        watcher.start_file_processor = mock.Mock()
        watcher.restart_file_processor(None, None)
        watcher.start_file_processor.assert_called_once_with()
        watcher.auto_restart_fileprocessor = False
        watcher.terminate(None, None)
        watcher.eventq.put.assert_called_with(as_metadata_manager.EOQ)

        handler = as_metadata_manager.EventHandler(watcher=mock.Mock(),
                                                  extensions='.ep')
        event = mock.Mock(pathname='/tmp/x.ep', maskname='IN_DELETE')
        handler.action(event)
        self.assertTrue(handler.watcher.action.called)

        mock_q = mock.Mock()
        mock_q.get.side_effect = [
            mock.Mock(maskname='IN_DELETE', pathname='/tmp/x.ep'),
            mock.Mock(maskname='IN_CLOSE_WRITE', pathname='/tmp/y.ep'),
            as_metadata_manager.EOQ,
        ]
        mock_q.get_nowait.side_effect = [
            mock.Mock(maskname='IN_MOVED_TO', pathname='/tmp/z.ep'),
            Queue.Empty,
        ]
        proc = as_metadata_manager.FileProcessor('/tmp', ['.ep'], mock_q,
                                                mock.Mock(return_value=True))
        proc.run()

    def test_as_metadata_manager_lifecycle_and_commands(self):
        mgr = as_metadata_manager.AsMetadataManager.__new__(
            as_metadata_manager.AsMetadataManager)
        mgr.root_helper = None
        mgr.name = 'mgr'
        mgr.md_filename = '/tmp/metadata.conf'
        mgr.bridge_manager = mock.Mock()
        mgr.initialized = False

        with mock.patch(
            'opflexagent.as_metadata_manager.subprocess.check_output',
            return_value=b'net 10.0.0.1/24') as check_output:
            self.assertEqual('net 10.0.0.1/24', mgr.sh('fake command'))
            self.assertIn('fake command',
                          check_output.call_args[0][0].decode())

        mgr.sh = mock.Mock()
        mgr.add_default_route('169.254.1.1')
        mgr.sh.assert_any_call('ip netns exec %s ip route add default via %s' %
                               (as_metadata_manager.SVC_NS,
                                '169.254.1.1'))

        mgr.sh.reset_mock()
        mgr.sh.return_value = 'net 169.254.1.2/16'
        self.assertTrue(mgr.has_ip('169.254.1.2'))
        self.assertFalse(mgr.has_ip('169.254.1.3'))

        mgr.sh.reset_mock()
        mgr.add_ip('169.254.1.2')
        mgr.del_ip('169.254.1.2')
        self.assertEqual(3, mgr.sh.call_count)

        mgr.sh.reset_mock()
        mgr.sh.return_value = 'link/ether aa:bb:cc:dd:ee:ff'
        self.assertIn('aa:bb:cc:dd:ee:ff', mgr.get_asport_mac())

        mgr.sh.reset_mock()
        mgr.sh.side_effect = lambda *args, **kwargs: ''
        mgr.init_host()
        mgr.bridge_manager.plug_metadata_port.assert_called_once()
        mgr.sh.side_effect = None

        mgr.write_file = mock.Mock()
        mgr.disable_proxy = True
        mgr.init_supervisor()
        self.assertTrue(mgr.write_file.called)
        mgr.write_file.reset_mock()

        mgr.disable_proxy = False
        mgr.init_supervisor()
        self.assertTrue(mgr.write_file.called)

        mgr.clean_files = mock.Mock()
        mgr.init_all = mock.Mock()
        mgr.ensure_initialized()
        self.assertTrue(mgr.initialized)

        mgr.initialized = True
        mgr.clean_files = mock.Mock()
        mgr.stop_supervisor = mock.Mock()
        mgr.ensure_terminated()
        self.assertFalse(mgr.initialized)

        mgr.sh.reset_mock()
        mgr.sh.return_value = ''
        mgr.add_default_route('fd00::a9fe:101', ip_version=6)
        mgr.sh.assert_any_call(
            'ip netns exec %s ip -6 route add default via %s dev %s' %
            (as_metadata_manager.SVC_NS, 'fd00::a9fe:101',
             as_metadata_manager.SVC_NS_PORT))

        ip6 = as_metadata_manager.SVC_V6_IP_DEFAULT
        mgr.sh.reset_mock()
        mgr.sh.return_value = 'net %s/64' % ip6
        self.assertTrue(mgr.has_ip(ip6))
        mgr.sh.reset_mock()
        mgr.sh.return_value = 'nope'
        self.assertFalse(mgr.has_ip(ip6))

        mgr.sh.reset_mock()
        mgr.add_ip(ip6)
        mgr.del_ip(ip6)
        self.assertEqual(3, mgr.sh.call_count)

        mgr.write_file = mock.Mock()
        mgr.disable_proxy = False
        mgr.init_supervisor()
        self.assertIn('metadata-agent', str(mgr.write_file.call_args[0][1]))

    def test_proxyconfig_legacy_link_local_next_hop(self):
        watcher = as_metadata_manager.StateWatcher.__new__(
            as_metadata_manager.StateWatcher)
        proxy = watcher.proxyconfig(legacy_curr_alloc_json[
            "44f67ef0-1fd8-7a7e-2bfb-e650cee859a9"])
        self.assertIn("--metadata_host fd00::a9fe:f003 --metadata_port=80",
                      proxy)
