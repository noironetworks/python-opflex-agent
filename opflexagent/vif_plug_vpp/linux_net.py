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

"""Creates VPP ports so that VPP renderer can add it to the right bridge."""

import opflexagent.vpplib.VPPApi as vpp_api
from opflexagent.vpplib.VPPApi import VPPApi
from oslo_log import log as logging
from vif_plug_vpp import constants

LOG = logging.getLogger(__name__)


def _create_vpp_vif(dev, iface_id, mac, mtu,
                    instance_id, interface_type=None,
                    vhost_server_path=None):
    vapi = VPPApi(LOG, 'nova_os_vif')
    # iface_id is the port UUID as seen in neutron. Use this as the tag
    # on the interface which will be later used as the key for endpoint lookup
    mac_address = vpp_api.mac_to_bytes(mac)
    if interface_type == constants.VPP_VHOSTUSER_CLIENT_INTERFACE_TYPE:
        sw_if_index = vapi.create_vhost_user_if(
                        str(vhost_server_path).encode('utf-8'),
                        0, mac_address, iface_id)
    else:
        sw_if_index = vapi.create_vhost_user_if(
                        str(vhost_server_path).encode('utf-8'),
                        1, mac_address, iface_id)
    LOG.debug("sw_if_index:{}".format(sw_if_index))
    if mtu:
        vapi.set_interface_mtu(sw_if_index, mtu)
    # Default admin state  for port in VPP is down, so do admin-up here
    vapi.set_interface_state(sw_if_index, 1)
    return sw_if_index


def create_vpp_vif_port(dev, iface_id, mac, instance_id,
                        mtu=None, interface_type=None, timeout=None,
                        vhost_server_path=None):
    sw_if_index = _create_vpp_vif(dev, iface_id, mac, mtu, instance_id,
                    interface_type,
                    vhost_server_path)
    return sw_if_index


def update_vpp_vif_port(dev, mtu=None, interface_type=None, timeout=None):
    if not mtu:
        return
    vapi = VPPApi(LOG, 'nova_os_vif')
    _, _, sw_if_index = vapi.vhost_details_from_tag(
        dev.port_profile.interface_id)
    vapi.set_interface_mtu(sw_if_index, mtu)


def delete_vpp_vif_port(dev, timeout=None, delete_netdev=True):
    vapi = VPPApi(LOG, 'nova_os_vif')
    vapi.delete_vhost_user_if(dev)
    return 0
