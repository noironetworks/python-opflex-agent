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

from opflexagent import host_agent_rpc
from opflexagent.utils.bridge_managers import ovs_lib
from opflexagent.utils import utils as agent_utils


class TestMiscCoverage(base.BaseTestCase):

    def test_get_bridge_manager_error_path(self):
        conf = mock.Mock(bridge_manager='does.not.exist')
        with mock.patch(
            'opflexagent.utils.utils.runtime.'
            'load_class_by_alias_or_classname',
            side_effect=ImportError('boom')):
            self.assertRaises(SystemExit, agent_utils.get_bridge_manager, conf)

    def test_ovsdb_transaction_and_fake_bridge(self):
        bridge = ovs_lib.OVSBridge.__new__(ovs_lib.OVSBridge)
        bridge._transaction = None

        txn = mock.Mock(name='txn')
        txn_cm = mock.MagicMock()
        txn_cm.__enter__.return_value = txn
        txn_cm.__exit__.return_value = None
        bridge.ovsdb = mock.Mock(transaction=mock.Mock(return_value=txn_cm))

        with bridge.ovsdb_transaction() as current_txn:
            self.assertEqual(txn, current_txn)
            self.assertEqual(txn, bridge._transaction)
        self.assertIsNone(bridge._transaction)

        bridge._transaction = txn
        with self.assertRaises(RuntimeError):
            with bridge.ovsdb_transaction() as current_txn:
                self.assertEqual(txn, current_txn)

        fake = ovs_lib.FakeOVSBridge.__new__(ovs_lib.FakeOVSBridge)
        port = fake.get_vif_port_by_id('port-id')
        self.assertEqual('port-id', port.vif_id)

    def test_host_agent_rpc_calls(self):
        client = mock.Mock()
        prepared = mock.Mock()
        prepared.call.return_value = 'ok'
        client.prepare.return_value = prepared

        with mock.patch('opflexagent.host_agent_rpc.rpc.get_client',
                        return_value=client):
            api = host_agent_rpc.ApicTopologyServiceNotifierApi()

        ctx = mock.Mock()
        self.assertEqual('ok', api.update_link(
            ctx, 'host1', 'eth0', 'aa:bb', 101, 1, 10, 2, 'descr'))
        self.assertEqual('ok', api.delete_link(ctx, 'host1', 'eth0'))

        self.assertEqual(2, prepared.call.call_count)
