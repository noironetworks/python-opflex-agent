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

from opflexagent import gbp_ovs_agent
from opflexagent.utils.port_managers import async_port_manager

from neutron.conf.agent import dhcp as dhcp_config
from neutron.tests import base
from oslo_config import cfg
from oslo_utils import uuidutils

_uuid = uuidutils.generate_uuid
EP_DIR = '.%s_endpoints/'


class TestAsyncPortManager(base.BaseTestCase):

    def setUp(self):
        cfg.CONF.register_opts(dhcp_config.DHCP_OPTS)
        super(TestAsyncPortManager, self).setUp()
        cfg.CONF.set_default('quitting_rpc_timeout', 10, 'AGENT')
        cfg.CONF.set_default('endpoint_request_timeout', 10000, 'OPFLEX')
        self.manager = self._initialize_agent()
        self.agent = self.manager.gbp_agent
        self.manager.pending_requests_by_request_id = (
            self.manager.pending_requests._pending_requests_by_request_id)
        self.manager.pending_requests_by_device_id = (
            self.manager.pending_requests._pending_requests_by_device_id)

    def _check_call_list(self, expected, observed, check_all=True):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        if check_all:
            self.assertFalse(
                len(observed),
                msg='There are more calls than expected: %s' % str(observed))

    def _initialize_agent(self):
        kwargs = gbp_ovs_agent.create_agent_config_map(cfg.CONF)
        agent = async_port_manager.AsyncPortManager().initialize(
            'h1', mock.Mock(), kwargs)
        agent.of_rpc = mock.Mock()
        return agent

    def _expire_update(self, ports_to_expire):
        for device in ports_to_expire:
            # Same reference is in the by_request_id dictionary
            self.manager.pending_requests_by_device_id[device]['timestamp'] = (
                -1)

    def _sort_requests(self, requests):
        return sorted(requests, key=lambda x: x['request_id'])

    def _get_device_requests(self, devices):
        return [self.manager.pending_requests_by_device_id[x] for x in devices]

    def test_initialized(self):
        self.assertEqual(10000, self.manager.request_timeout)

    def test_schedule_update(self):
        # There are no pending nor new requests, nothing happens
        self.manager.schedule_update()
        self.assertEqual(
            0, self.manager.of_rpc.request_endpoint_details_list.call_count)

        # Set new updates
        to_schedule = set(['1', '2', '3', '4'])
        self.manager.schedule_update(to_schedule)
        self.assertEqual(4, len(self.manager.pending_requests_by_request_id))
        self.assertEqual(4, len(self.manager.pending_requests_by_device_id))
        self.assertEqual(
            to_schedule,
            set(self.manager.pending_requests_by_device_id.keys()))
        self.assertEqual(
            set([x['request_id'] for x in
                 self.manager.pending_requests_by_device_id.values()]),
            set(self.manager.pending_requests_by_request_id.keys()))
        (self.manager.of_rpc.request_endpoint_details_list.
            assert_called_once_with(
                self.manager.context, agent_id=self.manager.agent_id,
                host=self.manager.host,
                requests=self._sort_requests(
                    self.manager.pending_requests_by_request_id.values())))

        self.manager.of_rpc.reset_mock()
        # The updates expired
        self._expire_update(ports_to_expire=set(['1', '3']))
        # Verify updates are reapplied
        self.manager.schedule_update(set())
        # timestamp refreshed and call reissued
        self.assertNotEqual(
            -1, self.manager.pending_requests_by_device_id['1']['timestamp'])
        self.assertNotEqual(
            -1, self.manager.pending_requests_by_device_id['3']['timestamp'])
        (self.manager.of_rpc.request_endpoint_details_list.
            assert_called_once_with(
                self.manager.context, agent_id=self.manager.agent_id,
                host=self.manager.host,
                requests=self._sort_requests(
                    self._get_device_requests(['1', '3']))))

        self.manager.of_rpc.reset_mock()
        # Verify expired and new ports requests
        self._expire_update(set(['2', '4']))
        self.manager.schedule_update(set(['5']))
        self.assertNotEqual(
            -1, self.manager.pending_requests_by_device_id['2']['timestamp'])
        self.assertNotEqual(
            -1, self.manager.pending_requests_by_device_id['4']['timestamp'])
        (self.manager.of_rpc.request_endpoint_details_list.
            assert_called_once_with(
                self.manager.context, agent_id=self.manager.agent_id,
                host=self.manager.host,
                requests=self._sort_requests(
                    self._get_device_requests(['2', '4', '5']))))

        self.manager.of_rpc.reset_mock()
        # Verify expired and new ports requests
        to_schedule = set(['1', '2', '3', '4', '5', '6'])
        self.manager.schedule_update(to_schedule)
        self.assertEqual(
            2, self.manager.of_rpc.request_endpoint_details_list.call_count)

    def test_opflex_update(self):
        # Set up some requests
        to_schedule = set(['1', '2', '3', '4'])
        self.manager.schedule_update(to_schedule)

        # Verify answer to some of them
        update = self._get_device_requests(['1', '3'])
        self.manager._opflex_endpoint_update(mock.Mock(), update)
        # Still pending until configuration apply happens
        self.assertTrue(
            '1' in self.manager.pending_requests_by_device_id)
        self.assertTrue(
            '3' in self.manager.pending_requests_by_device_id)
        self.assertTrue(
            update[0]['request_id'] in
            self.manager.pending_requests_by_request_id)
        self.assertTrue(
            update[1]['request_id'] in
            self.manager.pending_requests_by_request_id)
        self.assertTrue('1' in self.manager.response_by_device_id)
        self.assertTrue('3' in self.manager.response_by_device_id)

        # Ignore update
        update[0]['request_id'] = 'stuff'
        update[0]['device'] = '5'
        self.manager._opflex_endpoint_update(mock.Mock(), update[:1])
        # Update was ignored
        self.assertTrue('5' not in self.manager.response_by_device_id)

    def test_apply_config(self):
        self.agent.treat_devices_added_or_updated = mock.Mock(
            return_value=True)

        to_schedule = set(['1', '2', '3', '4'])
        self.manager.schedule_update(to_schedule)
        update = self._get_device_requests(['1', '2', '4'])
        self.manager._opflex_endpoint_update(mock.Mock(), update)
        expected_calls = [mock.call(self.manager.response_by_device_id[x])
                          for x in ['1', '2', '4']]
        self.manager.apply_config()
        # Removed from pending requests
        self.assertTrue(
            '1' not in self.manager.pending_requests_by_device_id)
        self.assertTrue(
            '2' not in self.manager.pending_requests_by_device_id)
        self.assertTrue(
            '4' not in self.manager.pending_requests_by_device_id)
        self._check_call_list(
            expected_calls,
            self.agent.treat_devices_added_or_updated.call_args_list)
        self.assertEqual({}, self.manager.response_by_device_id)

    def test_apply_config_fails(self):
        self.agent.treat_devices_added_or_updated = mock.Mock(
            side_effect=Exception)
        to_schedule = set(['1', '2', '3', '4'])
        self.manager.schedule_update(to_schedule)
        update = self._get_device_requests(['1', '2', '4'])
        self.manager._opflex_endpoint_update(mock.Mock(), update)
        self.assertRaises(Exception, self.manager.apply_config)
        # responses are restored after the exception
        self.assertEqual(3, len(self.manager.response_by_device_id))

    def test_unschedule_update(self):
        to_schedule = set(['1', '2', '3', '4'])
        self.manager.schedule_update(to_schedule)
        update = self._get_device_requests(['1', '3'])
        self.manager.unschedule_update(set(['1', '3']))
        self.assertTrue('1' not in self.manager.pending_requests_by_device_id)
        self.assertTrue('3' not in self.manager.pending_requests_by_device_id)
        self.assertTrue(update[0]['request_id'] not in
                        self.manager.pending_requests_by_request_id)
        self.assertTrue(update[1]['request_id'] not in
                        self.manager.pending_requests_by_request_id)
