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

from neutron.agent.common import ovs_lib
from neutron.common import constants as n_constants
from neutron.i18n import _LW
from neutron.plugins.openvswitch.common import constants
from oslo_log import log as logging
from oslo_serialization import jsonutils

from opflexagent.utils.bridge_managers import bridge_manager_base

LOG = logging.getLogger(__name__)
DEAD_VLAN_TAG = n_constants.MAX_VLAN_TAG + 1


class OvsManager(bridge_manager_base.BridgeManagerBase):
    """ Bridge Manager for OpenVSwitch."""

    def initialize(self, host, config):
        self.int_br_device_count = 0
        self.int_br = ovs_lib.OVSBridge(config['integ_br'])
        self.setup_integration_bridge()
        return self

    def check_bridge_status(self):
        # Check for the canary flow
        canary_flow = self.int_br.dump_flows_for_table(constants.CANARY_TABLE)
        if canary_flow == '':
            LOG.warn(_LW("OVS is restarted. OVSNeutronAgent will reset "
                         "bridges and recover ports."))
            return constants.OVS_RESTARTED
        elif canary_flow is None:
            LOG.warn(_LW("OVS is dead. OVSNeutronAgent will keep running "
                         "and checking OVS status periodically."))
            return constants.OVS_DEAD
        else:
            # OVS is in normal status
            return constants.OVS_NORMAL

    def setup_integration_bridge(self):
        """Override parent setup integration bridge."""
        self.int_br.create()
        self.int_br.set_secure_mode()

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

    def process_deleted_port(self, port_id):
        port = self.int_br.get_vif_port_by_id(port_id)
        # move to dead VLAN so deleted ports no
        # longer have access to the network
        if port:
            # don't log errors since there is a chance someone will be
            # removing the port from the bridge at the same time
            self.port_dead(port, log_errors=False)

    def port_dead(self, port, log_errors=True):
        """Once a port has no binding, put it on the "dead vlan".

        :param port: a ovs_lib.VifPort object.
        """
        pass

    def get_vif_port_by_ids(self, port_ids):
        args = ['--format=json', '--', '--columns=external_ids,name,ofport',
                'find', 'Interface',
                'external_ids:iface-id{<=}%s' % ','.join('"%s"' % x for
                                                       x in port_ids)]
        int_br = self.int_br
        LOG.debug("_get_vif_port_by_ids args: %s", args)
        iface_map = {}
        results = int_br.run_vsctl(args)
        if not results:
            return
        json_result = jsonutils.loads(results)
        # Retrieve the indexes of the columns we're looking for
        headings = json_result['headings']
        ext_ids_idx = headings.index('external_ids')
        name_idx = headings.index('name')
        ofport_idx = headings.index('ofport')
        for data in json_result['data']:
            port_id = None
            try:
                # If data attribute is missing or empty the line below will
                # raise an exeception which will be captured in this block.
                ext_id_dict = dict((item[0], item[1]) for item in
                                   data[ext_ids_idx][1])
                LOG.debug('ext_id_dict: %s', ext_id_dict)
                if 'iface-id' not in ext_id_dict:
                    # Not an interface
                    continue
                port_name = data[name_idx]
                port_id = ext_id_dict['iface-id']
                # REVISIT(ivar): we assume iface-id won't collide
                # (it's a UUID after all)
                # switch = get_bridge_for_iface(self.root_helper, port_name)
                # if switch != self.br_name:
                #    LOG.info(_("Port: %(port_name)s is on %(switch)s,"
                #               " not on %(br_name)s"),
                #               {'port_name': port_name,
                #                'switch': switch, 'br_name': self.br_name})
                #    return
                ofport = data[ofport_idx]
                # ofport must be integer otherwise return None
                if not isinstance(ofport, int) or ofport == -1:
                    LOG.warn(_("ofport: %(ofport)s for VIF: %(vif)s is not a "
                               "positive integer"), {'ofport': ofport,
                                                     'vif': port_id})
                    return
                # Find VIF's mac address in external ids
                vif_mac = ext_id_dict['attached-mac']
                iface_map[port_id] = ovs_lib.VifPort(
                    port_name, ofport, port_id, vif_mac, self)
            except Exception as e:
                LOG.warn(_("Unable to parse interface details. for port "
                           "%(port)s Exception: %(exc)s"), {'port': port_id,
                                                            'exc': e})
                continue
        return iface_map
