# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron import context as n_context
from neutron.services.trunk import constants
from neutron.services.trunk.rpc import agent
from oslo_context import context as o_context
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class OpflexTrunkMixin(agent.TrunkSkeleton):

    def __init__(self):
        super(OpflexTrunkMixin, self).__init__()
        self.managed_trunks = {}
        registry.unsubscribe(self.handle_trunks, resources.TRUNK)
        self._context = n_context.get_admin_context_without_session()
        self.trunk_rpc = agent.TrunkStub()

    @property
    def context(self):
        self._context.request_id = o_context.generate_request_id()
        return self._context

    def handle_trunks(self, trunks, event_type):
        pass

    def handle_subports(self, subports, event_type):
        trunk_id = subports[0].trunk_id
        if trunk_id in self.managed_trunks:
            subport_ids = [subport.port_id for subport in subports]
            try:
                if event_type == events.CREATED:
                    # Wire patch ports, the agent loop will do the rest
                    self.add_patch_ports(subport_ids)
                elif event_type == events.DELETED:
                    self.delete_patch_ports(subport_ids)
            except Exception as e:
                LOG.error(
                    "Failed to %(event)s subport for trunk %(trunk_id)s: "
                    "%(reason)s", {'event': event_type, 'trunk_id': trunk_id,
                                   'reason': e})
                self.trunk_rpc.update_trunk_status(
                    self.context, trunk_id, constants.DEGRADED_STATUS)

    def manage_trunk(self, port):
        if getattr(port, 'trunk_details', None):
            trunk_id = port.trunk_details['trunk_id']
            master_id = port.trunk_details['master_port_id']
            self.managed_trunks[trunk_id] = master_id
            self.managed_trunks[master_id] = trunk_id
            self.trunk_rpc.update_trunk_status(self.context, trunk_id,
                                               constants.ACTIVE_STATUS)

    def unmanage_trunk(self, port_id):
        if port_id in self.managed_trunks:
            master_id = self.managed_trunks.pop(port_id, None)
            self.managed_trunks.pop(master_id, None)
