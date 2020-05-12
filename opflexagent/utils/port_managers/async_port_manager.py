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

import time

from neutron.agent import rpc as agent_rpc
from neutron_lib.agent import topics
from neutron_lib import context
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

from opflexagent import rpc
from opflexagent.utils.port_managers import port_manager_base as base

LOG = logging.getLogger(__name__)


class RequestMap(object):

    def __init__(self):
        self._pending_requests_by_device_id = {}
        self._pending_requests_by_request_id = {}

    def get_by_device_id(self, device_id):
        return self._pending_requests_by_device_id.get(device_id)

    def get_by_request_id(self, request_id):
        return self._pending_requests_by_request_id.get(request_id)

    def get_requests(self):
        return self._pending_requests_by_request_id.values()

    def update_request(self, request):
        # Add or replace
        # Remove current requests if any
        self.pop_by_device_id(request['device'])
        # Replace with new requests
        self._pending_requests_by_device_id[request['device']] = request
        self._pending_requests_by_request_id[request['request_id']] = request

    def pop_by_request_id(self, request_id):
        current_request = self._pending_requests_by_request_id.pop(
            request_id, {})
        self._pending_requests_by_device_id.pop(
            current_request.get('device'), None)
        return current_request or None

    def pop_by_device_id(self, device_id):
        current_request = self._pending_requests_by_device_id.pop(device_id,
                                                                  {})
        self._pending_requests_by_request_id.pop(
            current_request.get('request_id'), None)
        return current_request or None


class AsyncPortManager(base.PortManagerBase, rpc.OpenstackRpcMixin):
    """ Async Port Manager

    Uses asynchronous RPC APIs to retrieve information from the Neutron server.
    """

    def initialize(self, host, gbp_agent, config):
        self.agent_id = gbp_agent.agent_id
        self.gbp_agent = gbp_agent
        self._setup_rpc()
        self.pending_requests = RequestMap()
        self.response_by_device_id = {}
        self.request_timeout = config['endpoint_request_timeout'] * 1000
        self.host = host
        return self

    def apply_config(self):
        LOG.debug("Apply config, pending requests: %s. current responses: "
                  "%s" % (self.pending_requests._pending_requests_by_device_id,
                          self.response_by_device_id))
        skipped = []
        response_by_device_id_copy = self.response_by_device_id
        self.response_by_device_id = {}
        try:
            for details in response_by_device_id_copy.values():
                # Context switch might happen here
                if not self.gbp_agent.treat_devices_added_or_updated(details):
                    skipped.append(details['device'])
                # Remove the request after a configuration write without
                # errors. Leaving the request pending is useful in case of
                # exceptions raised by the method above, since timeout will
                # eventually kick in and the port will go to the right state.
                self.pending_requests.pop_by_request_id(details['request_id'])
        except Exception as e:
            LOG.debug("An exception has occurred.")
            with excutils.save_and_reraise_exception():
                # The upper layers will trigger the resync
                LOG.error("Configuration failed on port manager: %s",
                          str(e))
                # Newer responses take precedence over old ones.
                response_by_device_id_copy.update(self.response_by_device_id)
                self.response_by_device_id = response_by_device_id_copy
        return skipped

    def schedule_update(self, device_ids=None):
        current_time = int(round(time.time() * 1000))
        device_ids = set(device_ids or [])
        LOG.debug('Update initially scheduled for port ids %s', device_ids)
        # See if more ports need to be updated due to request timeout
        for request in list(self.pending_requests.get_requests()):
            if current_time - request['timestamp'] > self.request_timeout:
                LOG.info('Request %s has timed out, rescheduling',
                         request['request_id'])
                device_ids.add(request['device'])
                # Remove from the pending requests, concurrency is not a
                # concern because of how greenthreads work
                self.pending_requests.pop_by_request_id(request['request_id'])

        LOG.info('Update scheduled for port ids %s', device_ids)
        requests = []
        for device_id in device_ids:
            request = {'request_id': uuidutils.generate_uuid(),
                       'host': self.host, 'agent_id': self.agent_id,
                       'timestamp': current_time, 'device': device_id}
            requests.append(request)
            self.pending_requests.update_request(request)

        LOG.debug('Scheduled requests: %s', requests)
        if requests:
            self.of_rpc.request_endpoint_details_list(
                self.context, agent_id=self.agent_id,
                requests=sorted(requests, key=lambda x: x['request_id']),
                host=self.host)

    def unschedule_update(self, device_ids=None):
        LOG.info("Unschedule update request for devices %s", device_ids)
        for device_id in device_ids:
            self.pending_requests.pop_by_device_id(device_id)

    def _setup_rpc(self):
        self.context = context.get_admin_context_without_session()
        # Set GBP rpc API
        self.of_rpc = rpc.GBPServerRpcApi(rpc.TOPIC_OPFLEX)
        self.topic = topics.AGENT
        self.endpoints = [self]
        consumers = [[rpc.TOPIC_OPFLEX, rpc.ENDPOINT, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(
            self.endpoints, self.topic, consumers, start_listening=True)

    def _opflex_endpoint_update(self, context, details):
        # Don't worry about concurrency, greenthreads won't be scheduled until
        # an explicit IO call is perfomed.
        LOG.info('Got endpoint update from the server')
        LOG.debug('The following updates were received: %s', details)
        for detail in details:
            if 'request_id' in detail:
                if not self.pending_requests.get_by_request_id(
                        detail['request_id']):
                    # This is a old request, ignore.
                    LOG.debug(
                        'Ignoring update with request ID %s as it is not '
                        'in the pending list', detail['request_id'])
                    continue
                self.response_by_device_id[detail['device']] = detail
            else:
                LOG.warn("Endpoint update for port %s is malformed "
                         "(request_id missing)" % detail.get('device'))
            LOG.debug("Got response for port %(port_id)s in "
                      "%(secs)s seconds",
                      {'port_id': detail.get('device'),
                       'secs': (((time.time() * 1000) -
                                 float(detail.get('timestamp', 0))) / 1000)})
