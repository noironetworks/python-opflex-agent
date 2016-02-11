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
from opflexagent.utils.bridge_managers import ovs_manager

from neutron.agent.dhcp import config as dhcp_config
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.tests import base
from oslo_config import cfg
from oslo_utils import uuidutils

_uuid = uuidutils.generate_uuid
EP_DIR = '.%s_endpoints/'


class TestOVSManager(base.BaseTestCase):

    def setUp(self):
        cfg.CONF.register_opts(dhcp_config.DHCP_OPTS)
        super(TestOVSManager, self).setUp()
        self.manager = self._initialize_agent()

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
        mock.patch('neutron.agent.common.ovs_lib.OVSBridge').start()
        agent = ovs_manager.OvsManager().initialize('h1', kwargs)
        return agent

    def test_bridge_status(self):
        # Restarted
        self.manager.int_br.dump_flows_for_table = mock.Mock(return_value='')
        self.assertEqual(constants.OVS_RESTARTED,
                         self.manager.check_bridge_status())
        # Dead
        self.manager.int_br.dump_flows_for_table = mock.Mock(return_value=None)
        self.assertEqual(constants.OVS_DEAD,
                         self.manager.check_bridge_status())
        # Normal
        self.manager.int_br.dump_flows_for_table = mock.Mock(return_value='1')
        self.assertEqual(constants.OVS_NORMAL,
                         self.manager.check_bridge_status())

    def test_scan_ports(self):
        # Nothing new
        curr = set(['1', '2', '3', '4'])
        self.manager.int_br.get_vif_port_set = mock.Mock(return_value=curr)
        res = self.manager.scan_ports(curr)
        self.assertEqual({'current': curr}, res)
        self.assertEqual(4, self.manager.int_br_device_count)

        # Ports added
        new_curr = curr | set(['5', '6'])
        self.manager.int_br.get_vif_port_set = mock.Mock(
            return_value= new_curr)
        res = self.manager.scan_ports(curr)
        self.assertEqual({'current': new_curr, 'added': set(['5', '6']),
                          'removed': set()}, res)
        self.assertEqual(6, self.manager.int_br_device_count)

        # Ports removed
        new_curr = curr - set(['1', '4'])
        self.manager.int_br.get_vif_port_set = mock.Mock(
            return_value=new_curr)
        res = self.manager.scan_ports(curr)
        self.assertEqual({'current': new_curr, 'added': set(),
                          'removed': set(['1', '4'])}, res)
        self.assertEqual(2, self.manager.int_br_device_count)

        # Ports updated
        self.manager.int_br.get_vif_port_set = mock.Mock(return_value=curr)
        res = self.manager.scan_ports(curr, updated_ports=set(['1', '3', '5']))
        self.assertEqual({'current': curr, 'updated': set(['1', '3'])}, res)

        res = self.manager.scan_ports(curr, updated_ports=set(['5']))
        self.assertEqual({'current': curr}, res)

    def test_process_deleted_port(self):
        self.manager.int_br.get_vif_port_by_id = mock.Mock(return_value='1')
        self.manager.port_dead = mock.Mock()

        self.manager.process_deleted_port('portid')
        self.manager.port_dead.assert_called_once_with('1', log_errors=False)

        self.manager.port_dead.reset_mock()
        self.manager.int_br.get_vif_port_by_id = mock.Mock(return_value=None)
        self.manager.process_deleted_port('portid')
        self.assertEqual(0, self.manager.port_dead.call_count)
