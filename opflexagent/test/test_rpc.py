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
sys.modules["apicapi"] = mock.Mock()
sys.modules["pyinotify"] = mock.Mock()

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
            mock.ANY, host='h1', requests=range(3))
        (self.callback.agent_notifier.opflex_endpoint_update.
            assert_called_once_with(mock.ANY, [result] * 3, host='h1'))

        # Test None return
        self.callback.agent_notifier.opflex_endpoint_update.reset_mock()
        result = None
        self.callback.gbp_driver.request_endpoint_details = mock.Mock(
            return_value=result)
        self.callback.request_endpoint_details_list(
            mock.ANY, host='h1', requests=range(3))
        self.assertFalse(
            self.callback.agent_notifier.opflex_endpoint_update.called)

    def test_request_vrf_details_list(self):
        result = {'device': 'someid'}
        self.callback.gbp_driver.request_vrf_details = mock.Mock(
            return_value=result)
        self.callback.request_vrf_details_list(
            mock.ANY, host='h1', requests=range(3))
        (self.callback.agent_notifier.opflex_vrf_update.
            assert_called_once_with(mock.ANY, [result] * 3, host='h1'))

        # Test None return
        self.callback.agent_notifier.opflex_vrf_update.reset_mock()
        result = None
        self.callback.gbp_driver.request_vrf_details = mock.Mock(
            return_value=result)
        self.callback.request_vrf_details_list(
            mock.ANY, host='h1', requests=range(3))
        self.assertFalse(
            self.callback.agent_notifier.opflex_vrf_update.called)

    def test_request_endpoint_details_list_batch(self):
        result = {'device': 'someid'}
        self.callback.gbp_driver.request_endpoint_details = mock.Mock(
            return_value=result)
        self.assertEqual(
            0, self.callback.agent_notifier.opflex_endpoint_update.call_count)
        self.callback.request_endpoint_details_list(
            mock.ANY, host='h1', requests=range(11))
        self.assertEqual(
            3, self.callback.agent_notifier.opflex_endpoint_update.call_count)
