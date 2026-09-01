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

    def test_request_snat_details(self):
        result = {'snat_uuid': 'snat-1'}
        self.callback.gbp_driver.request_snat_details = mock.Mock(
            return_value=result)
        self.callback.request_snat_details(mock.ANY, host='h1')
        (self.callback.agent_notifier.opflex_snat_update.
            assert_called_once_with(mock.ANY, [result], host='h1'))

        # Test None return
        self.callback.agent_notifier.opflex_snat_update.reset_mock()
        result = None
        self.callback.gbp_driver.request_snat_details = mock.Mock(
            return_value=result)
        self.callback.request_snat_details(mock.ANY, host='h1')
        self.assertFalse(
            self.callback.agent_notifier.opflex_snat_update.called)

    def test_request_snat_details_list(self):
        result = {'snat_uuid': 'snat-1'}
        self.callback.gbp_driver.request_snat_details = mock.Mock(
            return_value=result)
        self.callback.request_snat_details_list(
            mock.ANY, host='h1', requests=list(range(3)))
        (self.callback.agent_notifier.opflex_snat_update.
            assert_called_once_with(mock.ANY, [result] * 3, host='h1'))

        # Test None return
        self.callback.agent_notifier.opflex_snat_update.reset_mock()
        result = None
        self.callback.gbp_driver.request_snat_details = mock.Mock(
            return_value=result)
        self.callback.request_snat_details_list(
            mock.ANY, host='h1', requests=list(range(3)))
        self.assertFalse(
            self.callback.agent_notifier.opflex_snat_update.called)

    def test_get_snat_details_list(self):
        self.callback.gbp_driver.get_snat_details = mock.Mock(
            side_effect=lambda _ctx, snat_id=None, **_kwargs: {
                'snat_uuid': snat_id})
        result = self.callback.get_snat_details_list(
            mock.ANY, host='h1', snat_ids=['s1', 's2'])

        self.assertEqual([
            {'snat_uuid': 's1'},
            {'snat_uuid': 's2'}
        ], result)
