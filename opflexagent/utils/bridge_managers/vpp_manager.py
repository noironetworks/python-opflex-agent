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

import os

from neutron.agent.linux import ip_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron_lib import constants as lib_constants
from oslo_log import log as logging

from opflexagent import constants as ofcst
from opflexagent.utils.bridge_managers import bridge_manager_base
from opflexagent.utils.bridge_managers import trunk_skeleton
from opflexagent.vpplib.VPPApi import VPPApi

LOG = logging.getLogger(__name__)


class VppManager(bridge_manager_base.BridgeManagerBase,
                 trunk_skeleton.OpflexTrunkMixin):
    """ Bridge Manager for VPP."""

    def __init__(self):
        super(VppManager, self).__init__()

    def initialize(self, host, conf, agent_state):
        self.int_br_device_count = 0
        vpp_config = conf.VPP
        agent_state['agent_type'] = ofcst.AGENT_TYPE_OPFLEX_VPP
        if 'configurations' not in agent_state:
            agent_state['configurations'] = {}
        # only supported datapath type with VPP is netdev
        agent_state['configurations']['datapath_type'] = 'netdev'
        agent_state['configurations']['vhostuser_socket_dir'] = (
            vpp_config.vhostuser_socket_dir)
        return self, agent_state

    def get_local_ip(self):
        return None

    def check_bridge_status(self):
        vapi = VPPApi(LOG, 'gbp-agent')
        version = vapi.get_version()
        if (version['retval'] == 0) and version['version']:
            return constants.OVS_NORMAL
        return constants.OVS_DEAD

    def setup_integration_bridge(self):
        """Override parent setup integration bridge.
        VPP renderer handles the bridge creation.
        Nothing to do here
        """
        pass

    def scan_ports(self, registered_ports, updated_ports=None, em=None):
        cur_tag_dict = self.get_vif_port_set()
        cur_ports = {x for x, y in cur_tag_dict.items()}
        self.int_br_device_count = len(cur_ports)
        port_info = {'current': cur_ports}
        updated_ports = updated_ports or set()
        if updated_ports:
            # Some updated ports might have been removed in the
            # meanwhile, and therefore should not be processed.
            # In this case the updated port won't be found among
            # current ports.
            updated_ports &= cur_ports
            if updated_ports:
                port_info['updated'] = updated_ports

        if cur_ports == registered_ports:
            # No added or removed ports to set, just return here
            return port_info

        port_info['added'] = cur_ports - registered_ports
        # Remove all the known ports not found on the integration bridge
        port_info['removed'] = registered_ports - cur_ports
        # Retain ep file if nova is still holding on to the socket
        # or if tap interface is still present
        retain_list = set()
        removed_eps = port_info['removed']
        port_info['removed'] = self.handle_removed_eps(em, removed_eps)
        retain_list = removed_eps - port_info['removed']
        port_info['current'] |= retain_list
        return port_info

    # This is redundant since we populate port_name in get_vif_port_by_id
    def get_port_vif_name(self, port_id, bridge=None):
        return None

    # Stubbed for EP file
    def get_patch_port_pair_names(self, port_id):
        return ("", "")

    # VPP renderer handles the patch ports internally
    def add_patch_ports(self, port_ids, attached_macs=None):
        pass

    def delete_patch_ports(self, port_ids):
        pass

    def process_deleted_port(self, port_id):
        pass

    def port_dead(self, port, log_errors=True):
        pass

    def get_vif_port_by_id(self, tag):
        vapi = VPPApi(LOG, 'gbp-agent')
        port_name, mac, _ = vapi.vhost_details_from_tag(tag)
        # Create a fake port object for compatibility within
        # gbp agent.

        class Port(object):
            pass

        port_obj = Port()
        port_obj.vif_id = tag
        port_obj.vif_mac = mac
        port_obj.ofport = -1
        port_obj.port_name = port_name
        return port_obj

    def get_vif_port_set(self):
        """get list of host port macs

        :param : None.
        """
        vapi = VPPApi(LOG, 'gbp-agent')
        vhtag = vapi.get_vhost_tag_dicts()
        uuid_filtered = {x.split('|')[0]: y for x, y in vhtag.items()}
        return uuid_filtered

    @staticmethod
    def _device_exists(device_name):
        if device_name:
            if device_name.startswith(lib_constants.VETH_DEVICE_PREFIX):
                return ip_lib.device_exists(device_name)
            else:
                return os.path.exists(device_name)
        else:
            return False

    def handle_removed_eps(self, em, removed_eps):
        retain = set()
        for ep in removed_eps:
            port_name = em.get_access_int_for_vif(ep)
            if self._device_exists(port_name):
                LOG.debug("Retaining {}".format(port_name))
                retain |= {ep}
        removed_eps -= retain
        return removed_eps

    def plug_metadata_port(self, dst_shell, port):
        dst_shell("vppctl create host-interface name %s" % port)
        dst_shell("vppctl set interface state %s up" % port)

    # The following methods are called with host-interfaces for SNAT
    # This feature is currently not implemented by VPP
    # Hence stubbing it out
    def delete_port(self, port):
        pass

    def add_port(self, port, type_tuple):
        pass

    def get_port_name_list(self):
        return []
