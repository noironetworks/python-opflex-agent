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

from neutron.common import log
from neutron.common import rpc as n_rpc
from neutron.common import topics
from oslo_log import log as logging
import oslo_messaging

LOG = logging.getLogger(__name__)

TOPIC_OPFLEX = 'opflex'


class AgentNotifierApi(object):

    BASE_RPC_API_VERSION = '1.1'

    def __init__(self, topic):
        target = oslo_messaging.Target(
            topic=topic, version=self.BASE_RPC_API_VERSION)
        self.client = n_rpc.get_client(target)
        self.topic_port_update = topics.get_topic_name(topic, topics.PORT,
                                                       topics.UPDATE)
        self.topic_subnet_update = topics.get_topic_name(topic, topics.SUBNET,
                                                         topics.UPDATE)

    def port_update(self, context, port):
        cctxt = self.client.prepare(fanout=True, topic=self.topic_port_update)
        cctxt.cast(context, 'port_update', port=port)

    def subnet_update(self, context, subnet):
        cctxt = self.client.prepare(fanout=True,
                                    topic=self.topic_subnet_update)
        cctxt.cast(context, 'subnet_update', subnet=subnet)


class GBPServerRpcApiMixin(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction."""

    GBP_RPC_VERSION = "1.0"

    def __init__(self, topic):
        target = oslo_messaging.Target(
                topic=topic, version=self.GBP_RPC_VERSION)
        self.client = n_rpc.get_client(target)

    @log.log
    def get_gbp_details(self, context, agent_id, device=None, host=None):
        cctxt = self.client.prepare(version=self.GBP_RPC_VERSION)
        return cctxt.call(context, 'get_gbp_details', agent_id=agent_id,
                          device=device, host=host)

    @log.log
    def get_gbp_details_list(self, context, agent_id, devices=None, host=None):
        cctxt = self.client.prepare(version=self.GBP_RPC_VERSION)
        return cctxt.call(context, 'get_gbp_details_list', agent_id=agent_id,
                          devices=devices, host=host)

    @log.log
    def get_vrf_details(self, context, agent_id, vrf_id=None, host=None):
        cctxt = self.client.prepare(version=self.GBP_RPC_VERSION)
        return cctxt.call(context, 'get_vrf_details', agent_id=agent_id,
                          vrf_id=vrf_id, host=host)

    @log.log
    def get_vrf_details_list(self, context, agent_id, vrf_ids=None, host=None):
        cctxt = self.client.prepare(version=self.GBP_RPC_VERSION)
        return cctxt.call(context, 'get_vrf_details_list', agent_id=agent_id,
                          vrf_ids=vrf_ids, host=host)

    @log.log
    def ip_address_owner_update(self, context, agent_id, ip_owner_info,
                                host=None):
        self.fanout_cast(context,
                         self.make_msg('ip_address_owner_update',
                                       agent_id=agent_id,
                                       ip_owner_info=ip_owner_info,
                                       host=host),
                         version=self.GBP_RPC_VERSION)


class GBPServerRpcCallback(object):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction."""

    # History
    #   1.0 Initial version

    RPC_API_VERSION = "1.0"
    target = oslo_messaging.Target(version=RPC_API_VERSION)

    def __init__(self, gbp_driver):
        self.gbp_driver = gbp_driver

    def get_gbp_details(self, context, **kwargs):
        return self.gbp_driver.get_gbp_details(context, **kwargs)

    def get_gbp_details_list(self, context, **kwargs):
        return [
            self.get_gbp_details(
                context,
                device=device,
                **kwargs
            )
            for device in kwargs.pop('devices', [])
        ]

    def get_vrf_details(self, context, **kwargs):
        return self.gbp_driver.get_vrf_details(context, **kwargs)

    def get_vrf_details_list(self, context, **kwargs):
        return [
            self.get_vrf_details(
                context,
                vrf_id=vrf_id,
                **kwargs
            )
            for vrf_id in kwargs.pop('vrf_ids', [])
        ]

    def ip_address_owner_update(self, context, **kwargs):
        self.gbp_driver.ip_address_owner_update(context, **kwargs)
