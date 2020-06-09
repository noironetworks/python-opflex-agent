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
class PortManagerBase(object):
    """ Port Manager base class

    Defines an interface between the GBP opflex Agent and the Neutron server.
    The port manager takes care of requesting and processing Neutron's ports
    related info. Uses the gbp_agent for applying ports' configuration.
    """

    @abc.abstractmethod
    def initialize(self, host, gbp_agent, config):
        """ Port Manager initialization method.

        This method will be called before any other.

        :param host: agent host
        :param gbp_agent: the gbp agent handler.
        :param config: configuration dictionary

        :returns: self
        """

    def apply_config(self):
        """ Apply Port config.

        Applies currently stored configuration to the datapath, using the
        gbp agent.

        :returns: list of skipper devices
        """

    def schedule_update(self, port_ids=None):
        """ Schedule port updates.

        Old unattended requests should be handled here as well

        :param port_ids: ports for which update is needed
        """

    def unschedule_update(self, port_ids=None):
        """ Unchedule port updates.

        Used in case of deleted or removed ports

        :param port_ids: ports for which update is not needed anymore
        """
