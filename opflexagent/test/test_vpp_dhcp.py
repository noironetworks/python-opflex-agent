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

import importlib
import os
import sys

from unittest import mock

from neutron.tests import base

os.environ['NO_VPP_PAPI'] = '1'
VPPLIB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
                                           'vpplib'))
if VPPLIB_PATH not in sys.path:
    sys.path.insert(0, VPPLIB_PATH)
parent = sys.modules.get('opflexagent')
if parent is not None and hasattr(parent, 'vpplib'):
    delattr(parent, 'vpplib')
for name in ['opflexagent.vpplib.VPPApi',
             'opflexagent.vpplib.vpp_papi_provider',
             'opflexagent.vpplib',
             'hook']:
    sys.modules.pop(name, None)


def tearDownModule():
    parent = sys.modules.get('opflexagent')
    if parent is not None and hasattr(parent, 'vpplib'):
        delattr(parent, 'vpplib')
    for name in ['opflexagent.vpplib.VPPApi',
                 'opflexagent.vpplib.vpp_papi_provider',
                 'opflexagent.vpplib',
                 'hook']:
        sys.modules.pop(name, None)


class TestVppDhcp(base.BaseTestCase):

    def setUp(self):
        super(TestVppDhcp, self).setUp()
        self.vpp_dhcp = importlib.import_module('opflexagent.vpp_dhcp')

    def test_plug_new_and_unplug(self):
        driver = self.vpp_dhcp.VppInterfaceDriver(mock.Mock())
        root_veth = mock.Mock()
        ns_veth = mock.Mock()
        vapi = mock.Mock()
        vapi.create_host_interface.return_value = 11
        ip_wrapper = mock.Mock()
        ip_wrapper.add_veth.return_value = (root_veth, ns_veth)
        with mock.patch('opflexagent.vpp_dhcp.ip_lib.IPWrapper',
                        return_value=ip_wrapper), \
                mock.patch('opflexagent.vpp_dhcp.VPPApi', return_value=vapi), \
                mock.patch.object(driver, 'set_mtu') as set_mtu:
            driver.plug_new('net', 'port-id', 'qvb123', 'aa:bb:cc:dd:ee:ff',
                            namespace='ns', mtu=1450)
        ip_wrapper.add_veth.assert_called_once_with(
            'qvo123', 'qvb123', namespace2='ns')
        root_veth.disable_ipv6.assert_called_once_with()
        ns_veth.link.set_address.assert_called_once_with('aa:bb:cc:dd:ee:ff')
        set_mtu.assert_called_once_with(
            'qvb123', 1450, namespace='ns', prefix=None)
        root_veth.link.set_up.assert_called_once_with()
        vapi.create_host_interface.assert_called_once_with(
            b'qvo123', mock.ANY, b'port-id')
        vapi.set_interface_mtu.assert_called_once_with(11, 1450)
        vapi.set_interface_state.assert_called_once_with(11, '1')

        device = mock.Mock()
        with mock.patch('opflexagent.vpp_dhcp.ip_lib.IPDevice',
                        return_value=device), \
                mock.patch('opflexagent.vpp_dhcp.VPPApi', return_value=vapi):
            driver.unplug('qvb123')
        vapi.delete_host_interface.assert_called_once_with(b'qvo123')
        device.link.delete.assert_called_once_with()

    def test_set_mtu_and_runtime_unplug_error(self):
        driver = self.vpp_dhcp.VppInterfaceDriver(mock.Mock())
        root_dev = mock.Mock()
        with mock.patch('opflexagent.vpp_dhcp.agent_interface._get_veth',
                        return_value=(root_dev, mock.Mock())):
            driver.set_mtu('qvb123', 1400)
        root_dev.link.set_mtu.assert_called_once_with(1400)

        with mock.patch('opflexagent.vpp_dhcp.ip_lib.IPDevice'), \
                mock.patch('opflexagent.vpp_dhcp.VPPApi') as vapi_cls:
            vapi_cls.return_value.delete_host_interface.side_effect = (
                RuntimeError)
            self.assertIsNone(driver.unplug('qvb123'))
