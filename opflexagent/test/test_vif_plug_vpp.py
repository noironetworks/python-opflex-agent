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


class TestVifPlugVpp(base.BaseTestCase):

    def setUp(self):
        super(TestVifPlugVpp, self).setUp()
        self.constants = importlib.import_module(
            'opflexagent.vif_plug_vpp.constants')
        self.exception = importlib.import_module(
            'opflexagent.vif_plug_vpp.exception')
        self.linux_net = importlib.import_module(
            'opflexagent.vif_plug_vpp.linux_net')
        self.vpp = importlib.import_module('opflexagent.vif_plug_vpp.vpp')

    def _ensure_os_vif_object_modules(self):
        import os_vif.objects.host_info as host_info
        import os_vif.objects.vif as vif

        self.vpp.objects.host_info = host_info
        self.vpp.objects.vif = vif

    def test_linux_net_create_vpp_vif_uses_server_mode_and_mtu(self):
        vapi = mock.Mock()
        vapi.create_vhost_user_if.return_value = 7
        with mock.patch('opflexagent.vif_plug_vpp.linux_net.VPPApi',
                        return_value=vapi):
            result = self.linux_net._create_vpp_vif(
                'dev', b'iface', 'aa:bb:cc:dd:ee:ff', 1500, 'instance',
                vhost_server_path='/tmp/socket')

        self.assertEqual(7, result)
        vapi.create_vhost_user_if.assert_called_once_with(
            b'/tmp/socket', 1, mock.ANY, b'iface')
        vapi.set_interface_mtu.assert_called_once_with(7, [1500, 0, 0, 0])
        vapi.set_interface_state.assert_called_once_with(7, 1)

    def test_linux_net_create_vpp_vif_uses_client_mode(self):
        vapi = mock.Mock()
        vapi.create_vhost_user_if.return_value = 8
        with mock.patch('opflexagent.vif_plug_vpp.linux_net.VPPApi',
                        return_value=vapi):
            self.linux_net.create_vpp_vif_port(
                'dev', b'iface', 'aa:bb:cc:dd:ee:ff', 'instance', mtu=None,
                interface_type=(
                    self.constants.VPP_VHOSTUSER_CLIENT_INTERFACE_TYPE),
                vhost_server_path='/tmp/socket')
        vapi.create_vhost_user_if.assert_called_once_with(
            b'/tmp/socket', 0, mock.ANY, b'iface')
        vapi.set_interface_mtu.assert_not_called()

    def test_linux_net_update_and_delete_vpp_vif_port(self):
        vapi = mock.Mock()
        vapi.vhost_details_from_tag.return_value = ('sock', 'mac', 9)
        dev = mock.Mock()
        dev.port_profile.interface_id = 'iface-id'
        with mock.patch('opflexagent.vif_plug_vpp.linux_net.VPPApi',
                        return_value=vapi):
            self.linux_net.update_vpp_vif_port(dev, mtu=1400)
            self.assertEqual(0, self.linux_net.delete_vpp_vif_port('sock'))
        vapi.set_interface_mtu.assert_called_once_with(9, 1400)
        vapi.delete_vhost_user_if.assert_called_once_with('sock')

    def test_linux_net_update_returns_when_mtu_missing(self):
        with mock.patch('opflexagent.vif_plug_vpp.linux_net.VPPApi') as vapi:
            self.assertIsNone(self.linux_net.update_vpp_vif_port(mock.Mock()))
        vapi.assert_not_called()

    def test_vpp_plugin_describe_and_port_name(self):
        self._ensure_os_vif_object_modules()
        plugin = self.vpp.VppPlugin.load('vpp')
        self.assertEqual('vhu12345678901', plugin.gen_port_name(
            self.constants.VPP_VHOSTUSER_PREFIX, '123456789012345'))
        self.assertEqual(self.constants.PLUGIN_NAME,
                         plugin.describe().plugin_name)

    def test_vpp_plugin_get_mtu_prefers_network_mtu(self):
        plugin = self.vpp.VppPlugin.load('vpp')
        plugin.config = mock.Mock(network_device_mtu=1500)
        vif = mock.Mock()
        vif.network.mtu = 1450
        self.assertEqual(1450, plugin._get_mtu(vif))
        vif.network.mtu = None
        self.assertEqual(1500, plugin._get_mtu(vif))

    def test_vpp_plugin_create_update_and_delete_ports(self):
        plugin = self.vpp.VppPlugin.load('vpp')
        plugin.config = mock.Mock(network_device_mtu=1500, vpp_api_timeout=30)
        vif = mock.Mock(id='abcdef1234567890', address='aa:bb')
        vif.network.mtu = None
        vif.port_profile.interface_id = 'iface-id'
        instance_info = mock.Mock(uuid='instance-id')
        with mock.patch('opflexagent.vif_plug_vpp.vpp.linux_net') as net:
            plugin._create_vif_port(vif, 'vhuabcdef', instance_info,
                                    interface_type='type')
            plugin._update_vif_port(vif, 'vhuabcdef')
            plugin._unplug_vhostuser(vif, instance_info)
        net.create_vpp_vif_port.assert_called_once_with(
            'vhuabcdef', 'iface-id', 'aa:bb', 'instance-id', 1500,
            timeout=30, interface_type='type')
        net.update_vpp_vif_port.assert_called_once_with(vif, 1500)
        net.delete_vpp_vif_port.assert_called_once_with('vhuabcdef12345')

    def test_vpp_plugin_validates_port_profile(self):
        plugin = self.vpp.VppPlugin.load('vpp')
        vif = object()
        self.assertRaises(self.exception.MissingPortProfile,
                          plugin.plug, vif, mock.Mock())
        self.assertRaises(self.exception.MissingPortProfile,
                          plugin.unplug, vif, mock.Mock())

    def test_vpp_plugin_plug_and_unplug_vhostuser_paths(self):
        self._ensure_os_vif_object_modules()
        plugin = self.vpp.VppPlugin.load('vpp')
        plugin.config = mock.Mock(network_device_mtu=1500, vpp_api_timeout=30)

        class GoodProfile(object):
            interface_id = 'iface-id'

        class GoodVhost(object):
            pass

        vif = GoodVhost()
        vif.id = 'abcdef1234567890'
        vif.address = 'aa:bb:cc:dd:ee:ff'
        vif.path = '/tmp/vhost.sock'
        vif.mode = 'client'
        vif.port_profile = GoodProfile()
        vif.network = mock.Mock(mtu=None)
        instance_info = mock.Mock(uuid='instance-id')

        with mock.patch.object(self.vpp.objects.vif,
                               'VIFPortProfileOpenVSwitch', GoodProfile), \
                mock.patch.object(self.vpp.objects.vif,
                                  'VIFVHostUser', GoodVhost), \
                mock.patch('opflexagent.vif_plug_vpp.vpp.linux_net') as net:
            plugin.plug(vif, instance_info)
            plugin.unplug(vif, instance_info)

        net.create_vpp_vif_port.assert_called_once_with(
            'vhuabcdef12345', 'iface-id', 'aa:bb:cc:dd:ee:ff',
            'instance-id', 1500, timeout=30,
            interface_type=self.constants.VPP_VHOSTUSER_INTERFACE_TYPE,
            vhost_server_path='/tmp/vhost.sock')
        net.delete_vpp_vif_port.assert_called_once_with('vhuabcdef12345')

    def test_vpp_plugin_rejects_wrong_profile(self):
        self._ensure_os_vif_object_modules()
        plugin = self.vpp.VppPlugin.load('vpp')

        class GoodProfile(object):
            pass

        class GoodVhost(object):
            pass

        class BadProfile(object):
            pass

        vif = GoodVhost()
        vif.port_profile = BadProfile()

        with mock.patch.object(self.vpp.objects.vif,
                               'VIFPortProfileOpenVSwitch', GoodProfile), \
                mock.patch.object(self.vpp.objects.vif,
                                  'VIFVHostUser', GoodVhost):
            self.assertRaises(self.exception.WrongPortProfile,
                              plugin.plug, vif, mock.Mock())
            self.assertRaises(self.exception.WrongPortProfile,
                              plugin.unplug, vif, mock.Mock())
