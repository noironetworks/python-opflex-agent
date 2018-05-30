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

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class EndpointManagerBase(object):
    """ Endpoint Manager base class

    Defines an interface between the GBP opflex Agent and the endpoint policy
    repository. The endpoint manager takes care of policy based connectivity,
    that includes NAT when applicable.
    """
    vrf_dict = {}

    @abc.abstractmethod
    def initialize(self, host, bridge_manager, config):
        """ EP Manager initialization method.

        This method will be called before any other.

        :param host: agent host
        :param bridge_manager: the integration bridge manager.
        :param config: configuration dictionary

        :returns: self
        """

    @abc.abstractmethod
    def declare_endpoint(self, port, mapping):
        """ Process Endpoint Mapping.

        This method takes care of processing server side mapping info into
        fruible data for the endpoint repository. When appropriate, this
        method will undeclare the endpoint altogether.

        :param port: Object that represents the Openstack port.
        :param mapping: dictionary containing info retrieved from the Openstack
         server. See the gbp_details RPC

        :return: None
        """

    @abc.abstractmethod
    def undeclare_endpoint(self, port_id):
        """ Undeclare Endpoint Mapping.

        This method takes care of undeclaring the Eendpoint
        :param port_id: ID of the Openstack port.

        :return: None
        """

    @abc.abstractmethod
    def get_registered_endpoints(self):
        """ Get registered endpoints.

        :return: set of port IDs for each endpoint registered in the EP
        directory
        """

    @abc.abstractmethod
    def get_stale_endpoints(self):
        """ Get stale endpoints that are not tracked by registered endpoints.

        :return: set of stale endpoint IDs
        """

    @abc.abstractmethod
    def get_access_int_for_vif(self, vif):
        """ Get access interface for a given vif id.

        :return: access interface name
        """
