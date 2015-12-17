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
ENDPOINT = 'endpoint'
VRF = 'vrf'


class AgentNotifierApi(object):
    """Server side notification API:

    - Version 1.2: add opflex update
    """

    BASE_RPC_API_VERSION = '1.2'

    def __init__(self, topic):
        target = oslo_messaging.Target(
            topic=topic, version=self.BASE_RPC_API_VERSION)
        self.client = n_rpc.get_client(target)
        self.topic_port_update = topics.get_topic_name(topic, topics.PORT,
                                                       topics.UPDATE)
        self.topic_subnet_update = topics.get_topic_name(topic, topics.SUBNET,
                                                         topics.UPDATE)
        self.topic_opflex_endpoint_update = topics.get_topic_name(
            topic, TOPIC_OPFLEX, ENDPOINT, topics.UPDATE)
        self.topic_opflex_vrf_update = topics.get_topic_name(
            topic, TOPIC_OPFLEX, VRF, topics.UPDATE)

    def port_update(self, context, port):
        cctxt = self.client.prepare(fanout=True, topic=self.topic_port_update)
        cctxt.cast(context, 'port_update', port=port)

    def subnet_update(self, context, subnet):
        cctxt = self.client.prepare(fanout=True,
                                    topic=self.topic_subnet_update)
        cctxt.cast(context, 'subnet_update', subnet=subnet)

    def opflex_endpoint_update(self, context, details, host=None):
        cctxt = self.client.prepare(fanout=True,
                                    topic=self.topic_opflex_endpoint_update,
                                    server=host)
        cctxt.cast(context, 'opflex_endpoint_update', details=details)

    def opflex_vrf_update(self, context, details):
        cctxt = self.client.prepare(fanout=True,
                                    topic=self.topic_opflex_vrf_update)
        cctxt.cast(context, 'opflex_vrf_update', details=details)


class GBPServerRpcApiMixin(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction.

    Version 1.1: add async request_* APIs
    """

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
    def request_gbp_details(self, context, agent_id, request=None, host=None):
        # Request is a tuple with the device_id as first element, and the
        # request ID as second element
        cctxt = self.client.prepare(version=self.GBP_RPC_VERSION, fanout=True)
        cctxt.cast(context, 'request_gbp_details', agent_id=agent_id,
                   request=request, host=host)

    @log.log
    def request_gbp_details_list(self, context, agent_id, requests=None,
                                 host=None):
        # Requests is a list of tuples with the device_id as first element,
        # and the request ID as second element
        cctxt = self.client.prepare(version=self.GBP_RPC_VERSION, fanout=True)
        cctxt.cast(context, 'request_gbp_details_list',
                   agent_id=agent_id, requests=requests, host=host)

    @log.log
    def request_vrf_details(self, context, agent_id, request=None, host=None):
        # Request is a tuple with the vrf_id as first element, and the
        # request ID as second element
        cctxt = self.client.prepare(version=self.GBP_RPC_VERSION, fanout=True)
        cctxt.cast(context, 'request_vrf_details', agent_id=agent_id,
                   request=request, host=host)

    @log.log
    def request_vrf_details_list(self, context, agent_id, requests=None,
                                 host=None):
        # Requests is a list of tuples with the vrf_id as first element,
        # and the request ID as second element
        cctxt = self.client.prepare(version=self.GBP_RPC_VERSION, fanout=True)
        cctxt.cast(context, 'request_vrf_details_list',
                   agent_id=agent_id, requests=requests, host=host)

    @log.log
    def ip_address_owner_update(self, context, agent_id, ip_owner_info,
                                host=None):
        cctxt = self.client.prepare(version=self.GBP_RPC_VERSION, fanout=True)
        cctxt.cast(context, 'ip_address_owner_update', agent_id=agent_id,
                   ip_owner_info=ip_owner_info, host=host)


class GBPServerRpcCallback(object):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction."""

    # History
    #   1.0 Initial version
    #   1.1 Async request_* APIs

    RPC_API_VERSION = "1.1"
    target = oslo_messaging.Target(version=RPC_API_VERSION)

    def __init__(self, gbp_driver, agent_notifier):
        self.gbp_driver = gbp_driver
        self.agent_notifier = agent_notifier

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

    def request_gbp_details(self, context, **kwargs):
        result = [self.gbp_driver.request_gbp_details(context, **kwargs)]
        # Notify the agent back once the answer is calculated
        self.agent_notifier.opflex_endpoint_update(context, result,
                                                   host=kwargs.get('host'))

    def request_gbp_details_list(self, context, **kwargs):
        result = [
            self.gbp_driver.request_gbp_details(
                context,
                request=request,
                **kwargs
            )
            for request in kwargs.pop('requests', [])
        ]

        # Notify the agent back once the answer is calculated
        self.agent_notifier.opflex_endpoint_update(context, result,
                                                   host=kwargs.get('host'))

    def request_vrf_details(self, context, **kwargs):
        result = [self.gbp_driver.request_vrf_details(context, **kwargs)]
        # Notify the agent back once the answer is calculated
        self.agent_notifier.opflex_vrf_update(context, result,
                                              host=kwargs.get('host'))

    def request_vrf_details_list(self, context, **kwargs):
        result = [
            self.gbp_driver.request_vrf_details(
                context,
                request=request,
                **kwargs
            )
            for request in kwargs.pop('requests', [])
        ]

        # Notify the agent back once the answer is calculated
        self.agent_notifier.opflex_vrf_update(context, result,
                                              host=kwargs.get('host'))

    def ip_address_owner_update(self, context, **kwargs):
        self.gbp_driver.ip_address_owner_update(context, **kwargs)
