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
import socket
import struct

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
