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

from neutron.plugins.common import constants as n_constants
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from oslo_log import log as logging

from opflexagent.utils.bridge_managers import bridge_manager_base
from opflexagent.utils.bridge_managers import ovs_lib
from opflexagent.utils.bridge_managers import trunk_skeleton


LOG = logging.getLogger(__name__)
DEAD_VLAN_TAG = n_constants.MAX_VLAN_TAG + 1
NIC_NAME_LEN = 14


class OvsManager(bridge_manager_base.BridgeManagerBase,
                 trunk_skeleton.OpflexTrunkMixin):
    """ Bridge Manager for OpenVSwitch."""

    def __init__(self):
        super(OvsManager, self).__init__()

    def initialize(self, host, ovs_config, opflex_conf):
        self.int_br_device_count = 0
        self.int_br = ovs_lib.OVSBridge(ovs_config.integration_bridge)
        self.fabric_br = ovs_lib.OVSBridge(opflex_conf.fabric_bridge)
        self.setup_integration_bridge()
        return self

    def check_bridge_status(self):
        # Check for the canary flow
        canary_flow = self.int_br.dump_flows_for_table(constants.CANARY_TABLE)
        if canary_flow == '':
            LOG.warn("OVS is restarted. OVSNeutronAgent will reset "
                     "bridges and recover ports.")
            return constants.OVS_RESTARTED
        elif canary_flow is None:
            LOG.warn("OVS is dead. OVSNeutronAgent will keep running "
                     "and checking OVS status periodically.")
            return constants.OVS_DEAD
        else:
            # OVS is in normal status
            return constants.OVS_NORMAL

    def setup_integration_bridge(self):
        """Override parent setup integration bridge."""
        self.int_br.create()
        self.int_br.set_secure_mode()
        self.int_br.set_protocols(protocols='[]')
        #self.int_br.reset_ofversion()

        self.fabric_br.create()
        self.fabric_br.set_secure_mode()
        self.fabric_br.set_protocols(protocols='[]')

        # Add a canary flow to int_br to track OVS restarts
        self.int_br.add_flow(table=constants.CANARY_TABLE, priority=0,
                             actions="drop")

    def scan_ports(self, registered_ports, updated_ports=None):
        cur_ports = self.int_br.get_vif_port_set()
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

    def get_port_vif_name(self, port_id, bridge=None):
        bridge = bridge or self.int_br
        ports = bridge.get_vifs_by_ids([port_id])
        if ports:
            return ports[port_id].port_name

    def get_patch_port_pair_names(self, port_id):
        return (("qpi%s" % port_id)[:NIC_NAME_LEN],
                ("qpf%s" % port_id)[:NIC_NAME_LEN])

    def _get_patch_peer_attrs(self, peer_name, port_id):
        return [('type', 'patch'), ('options', {'peer': peer_name}),
                ('external_ids', {'iface-id': port_id})]

    def add_patch_ports(self, port_ids):
        ovsdb = self.int_br.ovsdb
        with self.int_br.ovsdb_transaction() as txn:
            for port_id in port_ids:
                port_i, port_f = self.get_patch_port_pair_names(port_id)
                patch_int_attrs = self._get_patch_peer_attrs(port_f, port_id)
                patch_fab_attrs = self._get_patch_peer_attrs(port_i, port_id)
                txn.add(ovsdb.add_port(self.int_br.br_name, port_i))
                txn.add(ovsdb.db_set('Interface', port_i, *patch_int_attrs))
                txn.add(ovsdb.add_port(self.fabric_br.br_name, port_f))
                txn.add(ovsdb.db_set('Interface', port_f, *patch_fab_attrs))

    def delete_patch_ports(self, port_ids):
        ovsdb = self.int_br.ovsdb
        with self.int_br.ovsdb_transaction() as txn:
            for port_id in port_ids:
                port_i, port_f = self.get_patch_port_pair_names(port_id)
                txn.add(ovsdb.del_port(port_i, self.int_br.br_name))
                txn.add(ovsdb.del_port(port_f, self.fabric_br.br_name))

    def process_deleted_port(self, port_id):
        pass

    def port_dead(self, port, log_errors=True):
        pass
