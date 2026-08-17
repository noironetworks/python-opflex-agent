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

import json
import os
import shutil
import socket
import struct
import sys

from unittest import mock

from neutron.tests import base
from oslo_config import cfg

from opflexagent import opflex_notify


class TestOpflexNotify(base.BaseTestCase):

    def setUp(self):
        super(TestOpflexNotify, self).setUp()
        # Configure the Cisco APIC mechanism driver
        cfg.CONF.set_override('opflex_notify_socket_path',
                              '/the/path', 'OPFLEX')
        python_version_long = f"python{sys.version_info.major}." \
                              f"{sys.version_info.minor}"
        self.policy_d_path = os.path.join(
                sys.prefix, 'lib', python_version_long,
                'site-packages', 'neutron', 'tests', 'etc', 'policy.d')

        os.makedirs(self.policy_d_path, exist_ok=True)

    def tearDown(self):
        super(TestOpflexNotify, self).tearDown()
        shutil.rmtree(self.policy_d_path, ignore_errors=True)

    def test_notify_socket(self):
        """Verify message encoding and decoding is done properly."""
        msg = {'method': 'virtual-ip',
               'params': {
                   'uuid': 'foo',
                   'mac': 'bar',
                   'ip': '192.168.0.1'}}
        encoded_msg = bytearray(json.dumps(msg).encode('utf-8'))
        connect_msg = bytearray(json.dumps(
            {"method": "subscribe",
             "params": {"type": ["virtual-ip"]}}).encode('utf-8'))
        with mock.patch('os.path.exists') as mock_path:
            mock_path.return_value = True
            with mock.patch('socket.socket') as socket_create:
                self.agent = opflex_notify.OpflexNotifyAgent()
                self.agent._connect()
                socket_create.assert_has_calls([
                    mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
                    mock.call().connect('/the/path'),
                    mock.call().send(b'\x00\x00\x00;'),
                    mock.call().send(connect_msg)]
                )
                socket_create.reset_mock()
                socket_create.recv.side_effect = (
                    struct.pack('I',
                        socket.htonl(len(encoded_msg))), encoded_msg,)
                read_msg = self.agent._read_msg(socket_create)
                socket_create.assert_has_calls([
                    mock.call.recv(4),
                    mock.call.recv(len(encoded_msg))]
                )
                self.assertEqual(read_msg, ('foo', 'bar', '192.168.0.1'))

    def test_handle_sends_owner_updates_and_skips_empty_uuid(self):
        self.agent = opflex_notify.OpflexNotifyAgent()
        self.agent.of_rpc = mock.Mock()
        self.agent._handle(['port-1|extra', '', 'port-2'], 'aa:bb',
                           '192.168.0.2')

        self.agent.of_rpc.ip_address_owner_update.assert_has_calls([
            mock.call(self.agent.context, self.agent.agent_id,
                      {'port': 'port-1', 'ip_address_v4': '192.168.0.2',
                       'mac': 'aa:bb'}, host=self.agent.host),
            mock.call(self.agent.context, self.agent.agent_id,
                      {'port': 'port-2', 'ip_address_v4': '192.168.0.2',
                       'mac': 'aa:bb'}, host=self.agent.host),
        ])

    def test_handle_ignores_rpc_exception(self):
        self.agent = opflex_notify.OpflexNotifyAgent()
        self.agent.of_rpc = mock.Mock()
        self.agent.of_rpc.ip_address_owner_update.side_effect = Exception(
            'boom')
        self.assertIsNone(self.agent._handle(['port-1'], 'aa:bb', '1.1.1.1'))

    def test_connect_returns_none_when_socket_missing_or_connect_fails(self):
        self.agent = opflex_notify.OpflexNotifyAgent()
        with mock.patch('os.path.exists', return_value=False):
            self.assertIsNone(self.agent._connect())

        client = mock.Mock()
        client.connect.side_effect = RuntimeError('boom')
        with mock.patch('os.path.exists', return_value=True), \
                mock.patch('socket.socket', return_value=client):
            self.assertIsNone(self.agent._connect())
        client.close.assert_called_once_with()

    def test_read_msg_rejects_short_and_malformed_messages(self):
        self.agent = opflex_notify.OpflexNotifyAgent()

        client = mock.Mock()
        client.recv.return_value = b'bad'
        self.assertIsNone(self.agent._read_msg(client))

        client = mock.Mock()
        client.recv.side_effect = [struct.pack('I', socket.htonl(10)), b'bad']
        self.assertIsNone(self.agent._read_msg(client))

        client = mock.Mock()
        msg = bytearray(json.dumps({'method': 'virtual-ip'}).encode('utf-8'))
        client.recv.side_effect = [struct.pack('I', socket.htonl(len(msg))),
                                   msg]
        self.assertIsNone(self.agent._read_msg(client))

        client = mock.Mock()
        msg = bytearray(json.dumps(
            {'method': 'other', 'params': {}}).encode('utf-8'))
        client.recv.side_effect = [struct.pack('I', socket.htonl(len(msg))),
                                   msg]
        self.assertIsNone(self.agent._read_msg(client))

    def test_throttle_and_exit(self):
        self.agent = opflex_notify.OpflexNotifyAgent()
        with mock.patch('time.sleep') as sleep:
            self.agent._throttle()
        sleep.assert_called_once_with(1)

        client = mock.Mock()
        with mock.patch('sys.exit', side_effect=SystemExit) as exit_mock:
            self.assertRaises(SystemExit, self.agent._exit, client)
        client.close.assert_called_once_with()
        exit_mock.assert_called_once_with(0)

        client.close.side_effect = RuntimeError('boom')
        with mock.patch('sys.exit', side_effect=SystemExit):
            self.assertRaises(SystemExit, self.agent._exit, client)

    def test_run_returns_without_socket_and_processes_one_message(self):
        self.agent = opflex_notify.OpflexNotifyAgent()
        self.agent.sockname = None
        self.assertIsNone(self.agent.run())

        self.agent.sockname = '/socket'
        client = mock.Mock()
        with mock.patch.object(self.agent, '_connect', return_value=client), \
                mock.patch.object(self.agent, '_read_msg',
                                  side_effect=[(['port'], 'aa:bb', '1.1.1.1'),
                                               None]), \
                mock.patch.object(self.agent, '_handle') as handle, \
                mock.patch.object(self.agent, '_throttle',
                                  side_effect=[None, KeyboardInterrupt]), \
                mock.patch.object(self.agent, '_exit',
                                  side_effect=SystemExit) as exit_mock:
            self.assertRaises(SystemExit, self.agent.run)

        handle.assert_called_once_with(['port'], 'aa:bb', '1.1.1.1')
        client.close.assert_called_once_with()
        exit_mock.assert_called_once_with(client)

    def test_worker_and_main(self):
        with mock.patch('opflexagent.opflex_notify.config.init') as init, \
                mock.patch('opflexagent.opflex_notify.config.setup_logging'), \
                mock.patch('opflexagent.opflex_notify.utils.log_opt_values'), \
                mock.patch('multiprocessing.Process.start') as start:
            worker = opflex_notify.worker(initconfig=True, daemon=False)

        self.assertFalse(worker.daemon)
        start.assert_called_once_with()
        self.assertTrue(init.called)

        with mock.patch('opflexagent.opflex_notify.worker') as worker_mock:
            self.assertIsNone(opflex_notify.main())
        worker_mock.assert_called_once_with(initconfig=True, daemon=False)

    def test_worker_returns_none_on_initialization_error(self):
        with mock.patch('opflexagent.opflex_notify.config.init',
                side_effect=RuntimeError('boom')):
            self.assertIsNone(opflex_notify.worker(initconfig=True))
