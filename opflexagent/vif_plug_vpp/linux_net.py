# Derived from nova/network/linux_net.py
#
# Copyright (c) 2018 Cisco Systems Inc.
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

"""Implements vlans, bridges using linux utilities."""
import sys

from oslo_log import log as logging

from vif_plug_vpp import constants
from vpplib.VPPApi import VPPApi

LOG = logging.getLogger(__name__)


def mac_to_bytes(mac):
    return str(''.join(chr(int(x, base=16)) for x in mac.split(':')))


def _create_vpp_vif(dev, iface_id, mac,
                    instance_id, interface_type=None,
                    vhost_server_path=None):
    vapi = VPPApi(LOG, 'nova_os_vif')
    mac_address = mac_to_bytes(mac)
    if interface_type == constants.VPP_VHOSTUSER_CLIENT_INTERFACE_TYPE:
        vapi.create_vhost_user_if(str(vhost_server_path).encode('utf-8'))
    else:
        vapi.create_vhost_user_if(str(vhost_server_path).encode('utf-8'),
                                  1, mac_address)
    return 0


def create_vpp_vif_port(dev, iface_id, mac, instance_id,
                        mtu=None, interface_type=None, timeout=None,
                        vhost_server_path=None):
    _create_vpp_vif(dev, iface_id, mac, instance_id,
                    interface_type,
                    vhost_server_path)
    _update_device_mtu(dev, mtu, interface_type, timeout=timeout)


def update_vpp_vif_port(dev, mtu=None, interface_type=None, timeout=None):
    _update_device_mtu(dev, mtu, interface_type, timeout=timeout)


def delete_vpp_vif_port(dev, timeout=None, delete_netdev=True):
    vapi = VPPApi(LOG, 'nova_os_vif')
    vapi.delete_vhost_user_if(dev)
    return 0


# TBD
def _set_device_mtu(dev, mtu):
    pass


def _update_device_mtu(dev, mtu, interface_type=None, timeout=120):
    if not mtu:
        return
    if interface_type not in [
        constants.VPP_VHOSTUSER_INTERFACE_TYPE,
        constants.VPP_VHOSTUSER_CLIENT_INTERFACE_TYPE]:
        if sys.platform != constants.PLATFORM_WIN32:
            # Hyper-V with OVS does not support external programming of virtual
            # interface MTUs via netsh or other Windows tools.
            # When plugging an interface on Windows, we therefore skip
            # programming the MTU and fallback to DHCP advertisement.
            _set_device_mtu(dev, mtu)
    elif _vpp_supports_mtu_requests(timeout=timeout):
        _set_mtu_request(dev, mtu, timeout=timeout)
    else:
        LOG.debug("MTU not set on %(interface_name)s interface "
                  "of type %(interface_type)s.",
                  {'interface_name': dev,
                   'interface_type': interface_type})


# TBD: How does VPP set mtu?
def _set_mtu_request(dev, mtu, timeout=None):
    pass


# TBD: How does VPP set mtu?
def _vpp_supports_mtu_requests(timeout=None):
    return False
