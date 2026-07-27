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

from unittest import mock
sys.modules["apicapi"] = mock.Mock()  # noqa
sys.modules["pyinotify"] = mock.Mock()  # noqa

from opflexagent import rpc
from opflexagent.test import base


class TestOpflexRpc(base.OpflexTestBase):

    def setUp(self):
        super(TestOpflexRpc, self).setUp()
        self.callback = rpc.GBPServerRpcCallback(mock.Mock(), mock.Mock())

    def test_request_endpoint_details(self):
        result = {'device': 'someid'}
        self.callback.gbp_driver.request_endpoint_details = mock.Mock(
            return_value=result)
        self.callback.request_endpoint_details(mock.ANY, host='h1')
        (self.callback.agent_notifier.opflex_endpoint_update.
            assert_called_once_with(mock.ANY, [result], host='h1'))

        # Test None return
        self.callback.agent_notifier.opflex_endpoint_update.reset_mock()
        result = None
        self.callback.gbp_driver.request_endpoint_details = mock.Mock(
            return_value=result)
        self.callback.request_endpoint_details(mock.ANY, host='h1')
        self.assertFalse(
            self.callback.agent_notifier.opflex_endpoint_update.called)

    def test_request_vrf_details(self):
        result = {'device': 'someid'}
        self.callback.gbp_driver.request_vrf_details = mock.Mock(
            return_value=result)
        self.callback.request_vrf_details(mock.ANY, host='h1')
        (self.callback.agent_notifier.opflex_vrf_update.
            assert_called_once_with(mock.ANY, [result], host='h1'))

        # Test None return
        self.callback.agent_notifier.opflex_vrf_update.reset_mock()
        result = None
        self.callback.gbp_driver.request_vrf_details = mock.Mock(
            return_value=result)
        self.callback.request_vrf_details(mock.ANY, host='h1')
        self.assertFalse(
            self.callback.agent_notifier.opflex_vrf_update.called)

    def test_request_endpoint_details_list(self):
        result = {'device': 'someid'}
        self.callback.gbp_driver.request_endpoint_details = mock.Mock(
            return_value=result)
        self.callback.request_endpoint_details_list(
            mock.ANY, host='h1', requests=list(range(3)))
        (self.callback.agent_notifier.opflex_endpoint_update.
            assert_called_once_with(mock.ANY, [result] * 3, host='h1'))

        # Test None return
        self.callback.agent_notifier.opflex_endpoint_update.reset_mock()
        result = None
        self.callback.gbp_driver.request_endpoint_details = mock.Mock(
            return_value=result)
        self.callback.request_endpoint_details_list(
            mock.ANY, host='h1', requests=list(range(3)))
        self.assertFalse(
            self.callback.agent_notifier.opflex_endpoint_update.called)

    def test_request_distributed_snat_details(self):
        result = {'host': 'h1',
                  'host_snat_ips': [{'host_snat_ip': '200.0.0.10'}]}
        self.callback.gbp_driver.request_distributed_snat_details = mock.Mock(
            return_value=result)
        self.callback.request_distributed_snat_details(mock.ANY, host='h1')
        (self.callback.agent_notifier.opflex_distributed_snat_update.
            assert_called_once_with(mock.ANY, result, host='h1'))

        # Test None return
        update = self.callback.agent_notifier.opflex_distributed_snat_update
        update.reset_mock()
        result = None
        self.callback.gbp_driver.request_distributed_snat_details = mock.Mock(
            return_value=result)
        self.callback.request_distributed_snat_details(mock.ANY, host='h1')
        self.assertFalse(update.called)

    def test_request_distributed_snat_details_notifies_empty_result(self):
        result = {}
        self.callback.gbp_driver.request_distributed_snat_details = mock.Mock(
            return_value=result)
        self.callback.request_distributed_snat_details(mock.ANY, host='h1')
        (self.callback.agent_notifier.opflex_distributed_snat_update.
            assert_called_once_with(mock.ANY, result, host='h1'))

    def test_request_distributed_snat_details_rpc_api(self):
        client = mock.Mock()
        cctxt = client.prepare.return_value
        with mock.patch.object(rpc.n_rpc, 'get_client', return_value=client):
            rpc_api = rpc.GBPServerRpcApi(rpc.TOPIC_OPFLEX)

        rpc_api.request_distributed_snat_details(
            mock.ANY, agent_id='agent-id', host='h1')

        client.prepare.assert_called_once_with(version='1.2')
        cctxt.call.assert_called_once_with(
            mock.ANY, 'request_distributed_snat_details',
            agent_id='agent-id', host='h1')

    def test_opflex_distributed_snat_update_notifier_rpc_api(self):
        client = mock.Mock()
        cctxt = client.prepare.return_value
        with mock.patch.object(rpc.n_rpc, 'get_client', return_value=client):
            notifier = rpc.AgentNotifierApi('agent')

        details = {'host': 'h1', 'host_snat_ips': []}
        notifier.opflex_distributed_snat_update(
            mock.ANY, details, host='h1')

        client.prepare.assert_called_once_with(
            topic=notifier.topic_opflex_distributed_snat_update,
            server='h1', version='1.4')
        cctxt.cast.assert_called_once_with(
            mock.ANY, 'opflex_distributed_snat_update', details=details)

    def test_request_vrf_details_list(self):
        result = {'device': 'someid'}
        self.callback.gbp_driver.request_vrf_details = mock.Mock(
            return_value=result)
        self.callback.request_vrf_details_list(
            mock.ANY, host='h1', requests=list(range(3)))
        (self.callback.agent_notifier.opflex_vrf_update.
            assert_called_once_with(mock.ANY, [result] * 3, host='h1'))

        # Test None return
        self.callback.agent_notifier.opflex_vrf_update.reset_mock()
        result = None
        self.callback.gbp_driver.request_vrf_details = mock.Mock(
            return_value=result)
        self.callback.request_vrf_details_list(
            mock.ANY, host='h1', requests=list(range(3)))
        self.assertFalse(
            self.callback.agent_notifier.opflex_vrf_update.called)
