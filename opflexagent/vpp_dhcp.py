# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
#
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

import neutron.agent.linux.interface as agent_interface
from neutron.agent.linux.interface import LinuxInterfaceDriver
from neutron.agent.linux import ip_lib

from neutron_lib import constants as lib_constants
import opflexagent.vpplib.VPPApi as vpp_api
from opflexagent.vpplib.VPPApi import VPPApi
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class VppInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating bridge interfaces."""

    DEV_NAME_PREFIX = 'qvb'

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None, mtu=None):
        """Plugin the interface."""
        ip = ip_lib.IPWrapper()

        # Enable agent to define the prefix
        tap_name = device_name.replace(prefix or self.DEV_NAME_PREFIX,
                                       lib_constants.VETH_DEVICE_PREFIX)
        # Create ns_veth in a namespace if one is configured.
        root_veth, ns_veth = ip.add_veth(tap_name, device_name,
                                         namespace2=namespace)
        root_veth.disable_ipv6()
        ns_veth.link.set_address(mac_address)
        if mtu:
            self.set_mtu(device_name, mtu, namespace=namespace, prefix=prefix)
        else:
            LOG.warning("No MTU configured for port %s", port_id)
        root_veth.link.set_up()
        # VPP section
        mac_address = vpp_api.mac_to_bytes(mac_address)

        vapi = VPPApi(LOG, 'vpp_dhcp')
        sw_if_index = vapi.create_host_interface(str(tap_name).encode('utf-8'),
                                                 mac_address,
                                                 str(port_id).encode('utf-8'))
        if mtu:
            vapi.set_interface_mtu(sw_if_index, mtu)
        vapi.set_interface_state(sw_if_index, '1')

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""

        tap_name = device_name.replace(prefix or self.DEV_NAME_PREFIX,
                                       lib_constants.VETH_DEVICE_PREFIX)
        device = ip_lib.IPDevice(tap_name)
        try:
            vapi = VPPApi(LOG, 'vpp_dhcp')
            vapi.delete_host_interface(str(tap_name).encode('utf-8'))
            device.link.delete()
            LOG.debug("Unplugged interface '%s'", device_name)
        except RuntimeError:
            LOG.error("Failed unplugging interface '%s'",
                      device_name)

    def set_mtu(self, device_name, mtu, namespace=None, prefix=None):
        tap_name = device_name.replace(prefix or self.DEV_NAME_PREFIX,
                                       lib_constants.VETH_DEVICE_PREFIX)
        root_dev, ns_veth = agent_interface._get_veth(
            tap_name, device_name, namespace2=namespace)
        root_dev.link.set_mtu(mtu)
