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

from neutron.common import exceptions as exc
from neutron.plugins.ml2.drivers import helpers
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log as logging

from opflexagent._i18n import _
from opflexagent import constants

LOG = logging.getLogger(__name__)

flat_opts = [
    cfg.StrOpt('default_opflex_network',
               default='physnet1',
               help=_("Default opflex network for tenants."))
]

cfg.CONF.register_opts(flat_opts, "ml2_type_opflex")


class OpflexTypeDriver(helpers.BaseTypeDriver):

    def __init__(self):
        LOG.info("ML2 OpflexTypeDriver initialization complete")
        self.default_opflex_network = (cfg.CONF.ml2_type_opflex.
                                       default_opflex_network)
        super(OpflexTypeDriver, self).__init__()

    def get_type(self):
        return constants.TYPE_OPFLEX

    def initialize(self):
        pass

    def is_partial_segment(self, segment):
        return False

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if not physical_network:
            msg = _("physical_network required for opflex provider network")
            raise exc.InvalidInput(error_message=msg)

        for key, value in list(segment.items()):
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK,
                                     api.MTU]:
                msg = _("%s prohibited for opflex provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        # No resources to reserve
        segment[api.MTU] = self.get_mtu(segment[api.PHYSICAL_NETWORK])
        return segment

    def allocate_tenant_segment(self, session):
        return {api.NETWORK_TYPE: constants.TYPE_OPFLEX,
                api.PHYSICAL_NETWORK: self.default_opflex_network,
                api.MTU: self.get_mtu(self.default_opflex_network)}

    def release_segment(self, session, segment):
        # No resources to release
        pass

    def get_mtu(self, physical_network):
        seg_mtu = super(OpflexTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0
