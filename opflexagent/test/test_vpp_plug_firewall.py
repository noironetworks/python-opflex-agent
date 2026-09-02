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
import types

from unittest import mock

from neutron.tests import base

nova = types.ModuleType('nova')
nova_network = types.ModuleType('nova.network')
nova_model = types.ModuleType('nova.network.model')
nova_model.VIF_DETAILS_OVS_DATAPATH_NETDEV = 'netdev'
nova_model.NIC_NAME_LEN = 14
nova_os_vif_util = types.ModuleType('nova.network.os_vif_util')
nova_os_vif_util._nova_to_osvif_vif_vhostuser = mock.Mock()
nova_os_vif_util._get_vif_instance = mock.Mock()
nova_os_vif_util._set_vhostuser_settings = mock.Mock()
sys.modules.setdefault('nova', nova)
sys.modules.setdefault('nova.network', nova_network)
sys.modules.setdefault('nova.network.model', nova_model)
sys.modules.setdefault('nova.network.os_vif_util', nova_os_vif_util)

from opflexagent import vpp_plug_firewall


class TestVppPlugFirewall(base.BaseTestCase):

    def _ensure_os_vif_object_modules(self):
        import os_vif.objects.vif as vif

        vpp_plug_firewall.objects.vif = vif

    def test_noop_firewall_wraps_vhostuser_conversion(self):
        self._ensure_os_vif_object_modules()
        original = mock.Mock(side_effect=NotImplementedError)
        vif = {'details': {'vhostuser_vpp_plug': True},
               'id': 'port-id-1234567890',
               'ovs_interfaceid': 'iface-id'}
        with mock.patch.object(vpp_plug_firewall.os_vif_util,
                               '_nova_to_osvif_vif_vhostuser', original), \
                mock.patch.object(vpp_plug_firewall.os_vif_util,
                                  '_get_vif_instance',
                                  return_value=mock.Mock()) as get_vif, \
                mock.patch.object(vpp_plug_firewall.os_vif_util,
                                  '_set_vhostuser_settings') as settings:
            driver = vpp_plug_firewall.NoopFirewallDriver()
            result = (
                vpp_plug_firewall.os_vif_util.
                _nova_to_osvif_vif_vhostuser(vif))

        self.assertEqual(get_vif.return_value, result)
        settings.assert_called_once_with(vif, result)
        self.assertTrue(driver.instance_filter_exists(None, None))
        self.assertIsNone(driver.prepare_instance_filter(None, None))

    def test_noop_firewall_reraises_unhandled_vif(self):
        original = mock.Mock(side_effect=NotImplementedError)
        vif = {'details': {}, 'id': 'port-id'}
        with mock.patch.object(vpp_plug_firewall.os_vif_util,
                               '_nova_to_osvif_vif_vhostuser', original):
            vpp_plug_firewall.NoopFirewallDriver()
            self.assertRaises(
                NotImplementedError,
                vpp_plug_firewall.os_vif_util._nova_to_osvif_vif_vhostuser,
                vif)
