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

from neutron.objects import trunk as trunk_objects
from neutron.services.trunk.rpc import agent
from neutron_lib import context as n_context
from neutron_lib.services.trunk import constants
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

    def handle_trunks(self, context, resource_type, trunks, event_type):
        pass

    def handle_subports(self, context, resource_type, subports, event_type,
                        trunk_id=None, update_trunk_status=True):
        LOG.info("Handling subports %(subports)s event %(event)s",
                 {'subports': subports, 'event': event_type})
        trunk_status = constants.TRUNK_ACTIVE_STATUS
        if subports:
            trunk_id = trunk_id or subports[0].trunk_id
            if trunk_id in self.managed_trunks:
                # Bind subports
                try:
                    if event_type == events.CREATED:
                        subport_ids = [p.port_id for p in subports]
                        subport_bindings = (
                            self.trunk_rpc.update_subport_bindings(
                                self.context, subports))
                        subport_bindings = subport_bindings.get(trunk_id, [])
                        subports_mac = {p['id']: p['mac_address'] for p in
                                        subport_bindings}
                        # Wire patch ports, the agent loop will do the rest
                        self.add_patch_ports(subport_ids,
                                             attached_macs=subports_mac)
                        # Subport tracking for the trunk, add as we
                        # process subports being added.
                        self.managed_trunks[trunk_id].update(subport_ids)
                    elif event_type == events.DELETED:
                        update_trunk_status = False
                        subport_ids = [p.port_id for p in subports]
                        self.delete_patch_ports(subport_ids)
                        # Subport tracking for the trunk, remove as we
                        # process subports being deleted.
                        needs_trunk_update = False
                        for subport_id in subport_ids:
                            try:
                                self.managed_trunks[trunk_id].remove(
                                    subport_id)
                                needs_trunk_update = True
                            except KeyError:
                                continue
                        if update_trunk_status and not needs_trunk_update:
                            update_trunk_status = False
                    if update_trunk_status:
                        self.trunk_rpc.update_trunk_status(
                            self.context, trunk_id, trunk_status)
                except Exception as e:
                    LOG.error(
                        "Failed to %(event)s subport for trunk %(trunk_id)s: "
                        "%(reason)s", {'event': event_type,
                                       'trunk_id': trunk_id,
                                       'reason': e})
                    trunk_status = constants.TRUNK_DEGRADED_STATUS
                    try:
                        if update_trunk_status:
                            self.trunk_rpc.update_trunk_status(
                                self.context, trunk_id,
                                trunk_status)
                    except Exception as e:
                        LOG.error(
                            "Failed to update status for trunk %(trunk_id)s: "
                            "%(reason)s", {'trunk_id': trunk_id,
                                           'reason': e})
        return trunk_status

    def manage_trunk(self, port):
        LOG.debug("Managing trunk for port: %s", port)
        trunk_status = constants.TRUNK_ACTIVE_STATUS
        if getattr(port, 'trunk_details', None):
            trunk_id = port.trunk_details['trunk_id']
            master_id = port.trunk_details['master_port_id']
            # Track the subports in the trunk. Since we don't get a
            # notification on unbind - we have no way to clean up
            # the patch ports for the subports. We trigger the
            # clean up when our scan finds that the parent is not
            # present due to unplugging of the VM.
            self.managed_trunks.setdefault(trunk_id, set())
            self.managed_trunks[master_id] = trunk_id
            # Attach subports
            if port.vif_id == master_id:
                subports = [
                    trunk_objects.SubPort(
                        context=self.context,
                        trunk_id=trunk_id,
                        port_id=x['port_id'],
                        segmentation_type=x['segmentation_type'],
                        segmentation_id=x['segmentation_id'])
                    for x in port.trunk_details['subports']]
                trunk_status = self.handle_subports(
                    self.context, None, subports, events.CREATED,
                    trunk_id=trunk_id, update_trunk_status=False)
            self.trunk_rpc.update_trunk_status(self.context, trunk_id,
                                               trunk_status)

    def unmanage_trunk(self, port_id):
        if port_id in self.managed_trunks:
            master_id = self.managed_trunks.pop(port_id, None)
            # Delete the patch ports for the subports being tracked.
            self.delete_patch_ports(list(self.managed_trunks[master_id]))
            self.managed_trunks.pop(master_id, None)
