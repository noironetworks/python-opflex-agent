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


BRIDGE_MANAGER_NAMESPACE = 'opflexagent.utils.bridge_managers'


@six.add_metaclass(abc.ABCMeta)
class BridgeManagerBase(object):
    """ Bridge Manager base class

    Defines an interface between the GBP opflex Agent and the controlled
    bridge. Operations like scanning and status checking are delegated to this
    module.
    """
    int_br_device_count = 0
    int_br = None
    fabric_br = None

    @abc.abstractmethod
    def initialize(self, host, config, agent_state):
        """ Bridge Manager initialization method.

        This method will be called before any other.

        :param host: agent host
        :param config: configuration dictionary
        :param agent_state: neutron agent state dictionary

        :returns: self, agent_state
        """

    @abc.abstractmethod
    def check_bridge_status(self):
        """ Check Bridge Status.

        :return: 0(RESTARTED), 1(NORMAL) or 2(DEAD)
        """

    @abc.abstractmethod
    def setup_integration_bridge(self):
        """ Setup the main integration bridge.

        :return: None
        """

    @abc.abstractmethod
    def scan_ports(self, registered_ports, updated_ports=None, em=None):
        """ Scan Bridge ports.

        :param registered_ports: ports already managed by the agent.
        :param updated_ports: ports for which the Openstack server requested
        an update.
        :param em: endpoint file manager

        :return: None
        """

    @abc.abstractmethod
    def process_deleted_port(self, port_id):
        """ Process deleted port

        :param port_id: Openstack port id
        :return None
        """

    @abc.abstractmethod
    def port_dead(self, port, log_errors=True):
        """Once a port has no binding, put it on the "dead vlan".

        :param port: a ovs_lib.VifPort object.
        """

    @abc.abstractmethod
    def get_vif_port_by_id(self, id):
        """Get port object using given id.

        :param id: mac or device id of the guest device
        :return Port object
        """

    @abc.abstractmethod
    def handle_removed_eps(self, em, removed_eps):
        """
        prune the set of eps to be removed based
        on vhost-user socket files persisting

        :param em: endpoint file manager
        :param removed_eps: candidate set of vif_ids to remove
        :return set of ep to be removed
        """
