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

from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from opflexagent import constants as ofcst
from opflexagent.utils.bridge_managers import bridge_manager_base
from opflexagent.utils.bridge_managers import trunk_skeleton
from oslo_log import log as logging
from vpplib.VPPApi import VPPApi


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
        agent_state['vhostuser_socket_dir'] = vpp_config.vhostuser_socket_dir
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

    def scan_ports(self, registered_ports, updated_ports=None):
        cur_ports = self.get_vif_port_set()
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

    def get_vif_port_by_id(self, mac):
        vapi = VPPApi(LOG, 'gbp-agent')
        port_name = vapi.vhost_name_from_mac(mac)
        # Create a fake port object for compatibility within
        # gbp agent.

        class Port(object):
            pass

        port_obj = Port()
        port_obj.vif_id = mac
        port_obj.vif_mac = mac
        port_obj.ofport = -1
        port_obj.port_name = port_name
        return port_obj

    def get_vif_port_set(self):
        """get list of host port macs

        :param : None.
        """
        vapi = VPPApi(LOG, 'gbp-agent')
        vhost_set = vapi.get_vhost_macs()
        return vhost_set
