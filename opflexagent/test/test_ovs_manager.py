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

import contextlib
import sys

import mock
sys.modules["apicapi"] = mock.Mock()  # noqa
sys.modules["pyinotify"] = mock.Mock()  # noqa

from opflexagent.utils.bridge_managers import ovs_manager

from neutron.conf.agent import dhcp as dhcp_config
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
        self._initialize_agent()
        self.manager.int_br = mock.Mock()
        self.manager.fabric_br = mock.Mock()
        self.manager.int_br.ovsdb_transaction = self.fake_transaction
        self.manager.fabric_br.ovsdb_transaction = self.fake_transaction

    @contextlib.contextmanager
    def fake_transaction(self, *args, **kwargs):
        yield mock.Mock()

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
        mock.patch(
            'opflexagent.utils.bridge_managers.ovs_lib.OVSBridge').start()
        agent = {}
        self.manager, agent = ovs_manager.OvsManager().initialize('h1',
                                                    cfg.CONF,
                                                    agent)
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
            return_value=new_curr)
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

    def test_add_delete_patch_ports(self):
        self.manager.add_patch_ports(['port_id4321XXXXX', 'port_id5432XXXXX'])
        expected = [mock.call(self.manager.int_br.br_name, 'qpfport_id4321'),
                    mock.call(self.manager.fabric_br.br_name,
                              'qpiport_id4321'),
                    mock.call(self.manager.int_br.br_name, 'qpfport_id5432'),
                    mock.call(self.manager.fabric_br.br_name,
                              'qpiport_id5432')]
        self._check_call_list(
            expected,
            self.manager.int_br.ovsdb.add_port.call_args_list)
        expected = [mock.call('Interface', 'qpfport_id4321',
                              ('type', 'patch'),
                              ('options', {'peer': 'qpiport_id4321'}),
                              ('external_ids',
                               {'iface-id': 'port_id4321XXXXX'})),
                    mock.call('Interface', 'qpiport_id4321',
                              ('type', 'patch'),
                              ('options', {'peer': 'qpfport_id4321'}),
                              ('external_ids',
                               {'iface-id': 'port_id4321XXXXX'})),

                    mock.call('Interface', 'qpfport_id5432',
                              ('type', 'patch'),
                              ('options', {'peer': 'qpiport_id5432'}),
                              ('external_ids',
                               {'iface-id': 'port_id5432XXXXX'})),
                    mock.call('Interface', 'qpiport_id5432',
                              ('type', 'patch'),
                              ('options', {'peer': 'qpfport_id5432'}),
                              ('external_ids',
                               {'iface-id': 'port_id5432XXXXX'}))]
        self._check_call_list(
            expected,
            self.manager.int_br.ovsdb.db_set.call_args_list)

        self.manager.delete_patch_ports(['port_id1234XXXXX'])
        expected = [mock.call('qpfport_id1234', self.manager.int_br.br_name),
                    mock.call('qpiport_id1234',
                              self.manager.fabric_br.br_name)]
        self._check_call_list(
            expected,
            self.manager.int_br.ovsdb.del_port.call_args_list)
