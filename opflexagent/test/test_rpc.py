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

    def test_agent_notifier_api_casts_all_notifications(self):
        rpc_client = mock.Mock()
        with mock.patch('opflexagent.rpc.n_rpc.get_client',
                        return_value=rpc_client):
            notifier = rpc.AgentNotifierApi('topic')

        operations = [
            (notifier.port_update, ({'id': 'port'},), 'port_update',
             notifier.topic_port_update, '1.1', {'port': {'id': 'port'}},
             True),
            (notifier.port_delete, ('port-id',), 'port_delete',
             notifier.topic_port_delete, '1.1', {'port': 'port-id'}, True),
            (notifier.subnet_update, ({'id': 'subnet'},), 'subnet_update',
             notifier.topic_subnet_update, '1.1',
             {'subnet': {'id': 'subnet'}}, True),
            (notifier.opflex_notify_vrf, ('vrf-id',), 'opflex_notify_vrf',
             notifier.topic_opflex_notify_vrf, '1.3', {'vrf': 'vrf-id'},
             True),
            (notifier.opflex_notify_snat, ('snat-id',), 'opflex_notify_snat',
             notifier.topic_opflex_notify_snat, '1.4', {'snat': 'snat-id'},
             True),
            (notifier.opflex_endpoint_update, ([{'id': 'ep'}],),
             'opflex_endpoint_update', notifier.topic_opflex_endpoint_update,
             '1.2', {'details': [{'id': 'ep'}]}, False),
            (notifier.opflex_vrf_update, ([{'id': 'vrf'}],),
             'opflex_vrf_update', notifier.topic_opflex_vrf_update, '1.2',
             {'details': [{'id': 'vrf'}]}, True),
            (notifier.opflex_snat_update, ([{'id': 'snat'}],),
             'opflex_snat_update', notifier.topic_opflex_snat_update, '1.4',
             {'details': [{'id': 'snat'}]}, True),
        ]

        for (method, args, rpc_method, topic, version, kwargs,
             fanout) in operations:
            rpc_client.reset_mock()
            cctxt = rpc_client.prepare.return_value
            method('ctx', *args)
            prepare_kwargs = {'topic': topic, 'version': version}
            if fanout:
                prepare_kwargs['fanout'] = True
            else:
                prepare_kwargs['server'] = None
            rpc_client.prepare.assert_called_once_with(**prepare_kwargs)
            cctxt.cast.assert_called_once_with('ctx', rpc_method, **kwargs)

    def test_server_rpc_api_calls_plugin_methods(self):
        rpc_client = mock.Mock()
        cctxt = rpc_client.prepare.return_value
        with mock.patch('opflexagent.rpc.n_rpc.get_client',
                        return_value=rpc_client):
            api = rpc.GBPServerRpcApi('topic')

        call_operations = [
            (api.get_gbp_details,
             {'device': 'dev', 'host': 'host'}, 'get_gbp_details',
             rpc.GBPServerRpcApi.GBP_RPC_VERSION,
             {'agent_id': 'agent', 'device': 'dev', 'host': 'host'}),
            (api.get_gbp_details_list,
             {'devices': ['dev'], 'host': 'host'}, 'get_gbp_details_list',
             rpc.GBPServerRpcApi.GBP_RPC_VERSION,
             {'agent_id': 'agent', 'devices': ['dev'], 'host': 'host'}),
            (api.get_vrf_details,
             {'vrf_id': 'vrf', 'host': 'host'}, 'get_vrf_details',
             rpc.GBPServerRpcApi.GBP_RPC_VERSION,
             {'agent_id': 'agent', 'vrf_id': 'vrf', 'host': 'host'}),
            (api.get_vrf_details_list,
             {'vrf_ids': ['vrf'], 'host': 'host'}, 'get_vrf_details_list',
             rpc.GBPServerRpcApi.GBP_RPC_VERSION,
             {'agent_id': 'agent', 'vrf_ids': ['vrf'], 'host': 'host'}),
            (api.get_snat_details,
             {'snat_id': 'snat', 'host': 'host'}, 'get_snat_details',
             rpc.GBPServerRpcApi.DISTRIBUTED_SNAT_RPC_VERSION,
             {'agent_id': 'agent', 'snat_id': 'snat', 'host': 'host'}),
            (api.get_snat_details_list,
             {'snat_ids': ['snat'], 'host': 'host'}, 'get_snat_details_list',
             rpc.GBPServerRpcApi.DISTRIBUTED_SNAT_RPC_VERSION,
             {'agent_id': 'agent', 'snat_ids': ['snat'], 'host': 'host'}),
        ]

        for method, kwargs, rpc_method, version, expected in call_operations:
            rpc_client.reset_mock()
            cctxt.call.reset_mock(return_value=True)
            method('ctx', 'agent', **kwargs)
            rpc_client.prepare.assert_called_once_with(version=version)
            cctxt.call.assert_called_once_with('ctx', rpc_method, **expected)

        request_operations = [
            (api.request_endpoint_details, {'request': ('dev', 'req'),
                                            'host': 'host'},
             'request_endpoint_details', rpc.GBPServerRpcApi.GBP_RPC_VERSION,
             {'agent_id': 'agent', 'request': ('dev', 'req'), 'host': 'host'}),
            (api.request_endpoint_details_list, {'requests': [('dev', 'req')],
                                                 'host': 'host'},
             'request_endpoint_details_list',
             rpc.GBPServerRpcApi.GBP_RPC_VERSION,
             {'agent_id': 'agent', 'requests': [('dev', 'req')],
              'host': 'host'}),
            (api.request_vrf_details, {'request': ('vrf', 'req'),
                                       'host': 'host'},
             'request_vrf_details', rpc.GBPServerRpcApi.GBP_RPC_VERSION,
             {'agent_id': 'agent', 'request': ('vrf', 'req'), 'host': 'host'}),
            (api.request_vrf_details_list, {'requests': [('vrf', 'req')],
                                            'host': 'host'},
             'request_vrf_details_list', rpc.GBPServerRpcApi.GBP_RPC_VERSION,
             {'agent_id': 'agent', 'requests': [('vrf', 'req')],
              'host': 'host'}),
            (api.request_snat_details, {'request': ('snat', 'req'),
                                        'host': 'host'},
             'request_snat_details',
             rpc.GBPServerRpcApi.DISTRIBUTED_SNAT_RPC_VERSION,
             {'agent_id': 'agent', 'request': ('snat', 'req'),
              'host': 'host'}),
            (api.request_snat_details_list, {'requests': [('snat', 'req')],
                                             'host': 'host'},
             'request_snat_details_list',
             rpc.GBPServerRpcApi.DISTRIBUTED_SNAT_RPC_VERSION,
             {'agent_id': 'agent', 'requests': [('snat', 'req')],
              'host': 'host'}),
            (api.ip_address_owner_update, {'ip_owner_info': {'ip': '1.1.1.1'},
                                           'host': 'host'},
             'ip_address_owner_update', rpc.GBPServerRpcApi.GBP_RPC_VERSION,
             {'agent_id': 'agent', 'ip_owner_info': {'ip': '1.1.1.1'},
              'host': 'host'}),
        ]

        for (method, kwargs, rpc_method, version,
             expected) in request_operations:
            rpc_client.reset_mock()
            cctxt.call.reset_mock(return_value=True)
            method('ctx', 'agent', **kwargs)
            rpc_client.prepare.assert_called_once_with(version=version)
            cctxt.call.assert_called_once_with('ctx', rpc_method, **expected)

    def test_callback_getters_and_snat_notifications(self):
        self.callback.gbp_driver.get_gbp_details.return_value = {
            'device': 'd1'}
        self.assertEqual(
            [{'device': 'd1'}, {'device': 'd1'}],
            self.callback.get_gbp_details_list(
                'ctx', devices=['d1', 'd2'], host='host'))
        self.callback.gbp_driver.get_gbp_details.assert_has_calls([
            mock.call('ctx', device='d1', host='host'),
            mock.call('ctx', device='d2', host='host')])

        self.callback.gbp_driver.get_vrf_details.return_value = {'vrf': 'v1'}
        self.assertEqual(
            [{'vrf': 'v1'}, {'vrf': 'v1'}],
            self.callback.get_vrf_details_list(
                'ctx', vrf_ids=['v1', 'v2'], host='host'))
        self.callback.gbp_driver.get_vrf_details.assert_has_calls([
            mock.call('ctx', vrf_id='v1', host='host'),
            mock.call('ctx', vrf_id='v2', host='host')])

        self.callback.gbp_driver.get_snat_details.return_value = {'snat': 's1'}
        self.assertEqual({'snat': 's1'}, self.callback.get_snat_details(
            'ctx', snat_id='s1', host='host'))
        self.assertEqual(
            [{'snat': 's1'}, {'snat': 's1'}],
            self.callback.get_snat_details_list(
                'ctx', snat_ids=['s1', 's2'], host='host'))
        self.callback.gbp_driver.get_snat_details.assert_has_calls([
            mock.call('ctx', snat_id='s1', host='host'),
            mock.call('ctx', snat_id='s1', host='host'),
            mock.call('ctx', snat_id='s2', host='host')])

        self.callback.gbp_driver.request_snat_details.return_value = {
            'snat': 's1'}
        self.callback.request_snat_details('ctx', host='host')
        self.callback.agent_notifier.opflex_snat_update.assert_called_with(
            'ctx', [{'snat': 's1'}], host='host')
        self.callback.agent_notifier.opflex_snat_update.reset_mock()
        self.callback.request_snat_details_list(
            'ctx', requests=['r1', 'r2'], host='host')
        self.callback.agent_notifier.opflex_snat_update.\
            assert_called_once_with(
                'ctx', [{'snat': 's1'}, {'snat': 's1'}], host='host')

        self.callback.gbp_driver.ip_address_owner_update = mock.Mock()
        self.callback.ip_address_owner_update(
            'ctx', ip_owner_info={'ip': 'ip'})
        self.callback.gbp_driver.ip_address_owner_update.\
            assert_called_once_with('ctx', ip_owner_info={'ip': 'ip'})

    def test_openstack_rpc_mixin_updates_sets_and_delegates(self):
        class Agent(rpc.OpenstackRpcMixin):
            def __init__(self):
                self.updated_vrf = set()
                self.updated_snat = set()
                self.updated_ports = set()
                self.deleted_ports = set()
                self._opflex_endpoint_update = mock.Mock()
                self._opflex_vrf_update = mock.Mock()

        agent = Agent()
        agent.subnet_update('ctx', {'tenant_id': 'tenant', 'id': 'subnet'})
        agent.opflex_notify_vrf('ctx', 'vrf')
        agent.opflex_notify_snat('ctx', 'snat')
        agent.port_update('ctx', port={'id': 'port'})
        agent.port_delete('ctx', port_id='port')
        agent.opflex_endpoint_update('ctx', [{'id': 'ep'}])
        agent.opflex_vrf_update('ctx', [{'id': 'vrf'}])

        self.assertEqual(set(['tenant', 'vrf']), agent.updated_vrf)
        self.assertEqual(set(['snat']), agent.updated_snat)
        self.assertEqual(set(['port']), agent.updated_ports)
        self.assertEqual(set(['port']), agent.deleted_ports)
        agent._opflex_endpoint_update.assert_called_once_with(
            'ctx', [{'id': 'ep'}])
        agent._opflex_vrf_update.assert_called_once_with(
            agent, 'ctx', [{'id': 'vrf'}])
