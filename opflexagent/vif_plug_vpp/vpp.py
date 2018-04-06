# Derived from nova/virt/libvirt/vif.py
#
# Copyright (C) 2018 Cisco Systems Inc.
# Copyright 2011 OpenStack Foundation
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

from os_vif import objects
from os_vif import plugin
from oslo_config import cfg

from vif_plug_vpp import constants
from vif_plug_vpp import exception
from vif_plug_vpp import linux_net


class VppPlugin(plugin.PluginBase):
    """A VPP plugin that can setup VIFs in many ways

    The VPP plugin supports VIF type VIFOpenVSwitch,
    and will choose the appropriate plugging
    action depending on the type of VIF config it receives.
    """

    NIC_NAME_LEN = 14

    CONFIG_OPTS = (
        cfg.IntOpt('network_device_mtu',
                   default=1500,
                   help='MTU setting for network interface.',
                   deprecated_group="DEFAULT"),
        cfg.IntOpt('vpp_api_timeout',
                   default=120,
                   help='Amount of time, in seconds, that vpp_api should '
                   'wait for a response from the database. 0 is to wait '
                   'forever.',
                   deprecated_group="DEFAULT"),
    )

    @staticmethod
    def gen_port_name(prefix, id):
        return ("%s%s" % (prefix, id))[:VppPlugin.NIC_NAME_LEN]

    def describe(self):
        pp_ovs = objects.host_info.HostPortProfileInfo(
            profile_object_name=
            objects.vif.VIFPortProfileOpenVSwitch.__name__,
            min_version="1.0",
            max_version="1.0",
        )
        pp_ovs_representor = objects.host_info.HostPortProfileInfo(
            profile_object_name=
            objects.vif.VIFPortProfileOVSRepresentor.__name__,
            min_version="1.0",
            max_version="1.0",
        )
        return objects.host_info.HostPluginInfo(
            plugin_name=constants.PLUGIN_NAME,
            vif_info=[
                objects.host_info.HostVIFInfo(
                    vif_object_name=objects.vif.VIFBridge.__name__,
                    min_version="1.0",
                    max_version="1.0",
                    supported_port_profiles=[pp_ovs]),
                objects.host_info.HostVIFInfo(
                    vif_object_name=objects.vif.VIFOpenVSwitch.__name__,
                    min_version="1.0",
                    max_version="1.0",
                    supported_port_profiles=[pp_ovs]),
                objects.host_info.HostVIFInfo(
                    vif_object_name=objects.vif.VIFVHostUser.__name__,
                    min_version="1.0",
                    max_version="1.0",
                    supported_port_profiles=[pp_ovs, pp_ovs_representor]),
                objects.host_info.HostVIFInfo(
                    vif_object_name=objects.vif.VIFHostDevice.__name__,
                    min_version="1.0",
                    max_version="1.0",
                    supported_port_profiles=[pp_ovs, pp_ovs_representor]),
            ])

    def _get_mtu(self, vif):
        if vif.network and vif.network.mtu:
            return vif.network.mtu
        return self.config.network_device_mtu

    def _create_vif_port(self, vif, vif_name, instance_info, **kwargs):
        mtu = self._get_mtu(vif)
        linux_net.create_vpp_vif_port(
            vif_name,
            vif.port_profile.interface_id,
            vif.address, instance_info.uuid,
            mtu,
            timeout=self.config.vpp_api_timeout,
            **kwargs)

    def _update_vif_port(self, vif, vif_name):
        mtu = self._get_mtu(vif)
        linux_net.update_vpp_vif_port(vif_name, mtu)

    def _plug_vhostuser(self, vif, instance_info):
        vif_name = VppPlugin.gen_port_name(
            constants.VPP_VHOSTUSER_PREFIX, vif.id)
        args = {}
        if vif.mode == "client":
            args['interface_type'] = (
                constants.VPP_VHOSTUSER_INTERFACE_TYPE)
        else:
            args['interface_type'] = (
                constants.VPP_VHOSTUSER_CLIENT_INTERFACE_TYPE)
        args['vhost_server_path'] = vif.path

        self._create_vif_port(
            vif, vif_name, instance_info, **args)

    def plug(self, vif, instance_info):
        if not hasattr(vif, "port_profile"):
            raise exception.MissingPortProfile()
        if not isinstance(vif.port_profile,
                          objects.vif.VIFPortProfileOpenVSwitch):
            raise exception.WrongPortProfile(
                profile=vif.port_profile.__class__.__name__)

        if isinstance(vif, objects.vif.VIFVHostUser):
            self._plug_vhostuser(vif, instance_info)

    def _unplug_vhostuser(self, vif, instance_info):
        linux_net.delete_vpp_vif_port(VppPlugin.gen_port_name(
                                          constants.VPP_VHOSTUSER_PREFIX,
                                          vif.id)
                                      )

    def unplug(self, vif, instance_info):
        if not hasattr(vif, "port_profile"):
            raise exception.MissingPortProfile()
        if not isinstance(vif.port_profile,
                          objects.vif.VIFPortProfileOpenVSwitch):
            raise exception.WrongPortProfile(
                profile=vif.port_profile.__class__.__name__)

        if isinstance(vif, objects.vif.VIFVHostUser):
            self._unplug_vhostuser(vif, instance_info)
