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

import contextlib
from neutron.agent import firewall as fw
from oslo_log import log as logging
from oslo_utils import importutils


LOG = logging.getLogger(__name__)


class FirewallDriverWrapper(fw.FirewallDriver):
    """Wrapper for Firewall Driver implemntations

    This wrapper class keeps a map of strategies to
    use for implementing a firewall driver. The strategy
    selected is determined by a key, which is passed in
    a map as part of the init_wrapper function. The strategy
    must know how to select the appropriate firewall driver
    based solely on the key associated with that driver. The
    key should be obtained from the port object, or if no port
    object is supplied, it should return all of them
    """

    def __init__(self):
        self.strategy_map = {}
        self.strategy_fn = None
        self.default_strategy = None

    def strategy(self, port):
        """Return appropiate strategy object

        This returns the appropriate implementation of
        a FirewallDriver, based on the strategy function
        and strategy map provided. If no strategy object
        is found, then the default strategy object is
        returned. This is only valid for port-based
        API calls, which can select the right strategy
        based on port properties.
        """
        strategy_obj = self.default_strategy

        if self.strategy_map and self.strategy_fn:
            key = self.strategy_fn(port, self.strategy_map)
            if key:
                strategy_obj = self.strategy_map[key]
        return strategy_obj

    def set_strategy_and_map(self, strategy_map, strategy_fn, default):
        """Set Firewall Driver strategy and map

           This sets the strategy to call for selecting
           which firewall driver to use. It also provides
           the map the strategy uses for selecting it.
        """
        if not strategy_map and default is None:
            return

        # set default strategy if a map wasn't provided
        if not strategy_map:
            self.default_strategy = importutils.import_object(default)

        self.strategy_fn = strategy_fn

        # We need to go through and load each of the classes
        # in the firewall map and provide that in our map
        for element in strategy_map:
            key, value = element
            self.strategy_map[key] = importutils.import_object(value)

    def prepare_port_filter(self, port):
        self.strategy(port).prepare_port_filter(port)

    def apply_port_filter(self, port):
        self.strategy(port).apply_port_filter(port)

    def update_port_filter(self, port):
        self.strategy(port).update_port_filter(port)

    def remove_port_filter(self, port):
        self.strategy(port).remove_port_filter(port)

    # The following methods apply across all strategies
    def filter_defer_apply_on(self):
        """Turn on deferred apply

           This method is not port-based, and therefore must
           be invoked for all strategies. If the default is
           set, then use that instead
        """
        if self.default_strategy:
            self.default_strategy.filter_defer_apply_on()
            return

        for driver in self.strategy_map.values():
            driver.filter_defer_apply_on()

    def filter_defer_apply_off(self):
        """Turn off deferred apply

           This method is not port-based, and therefore must
           be invoked for all strategies. If the default is
           set, then use that instead
        """
        if self.default_strategy:
            self.default_strategy.filter_defer_apply_off()
            return

        for driver in self.strategy_map.values():
            driver.filter_defer_apply_off()

    @property
    def ports(self):
        """Get all the ports for security groups

           This method is not port-based, and therefore must
           be invoked for all strategies. If the default is
           set, then use that instead
        """
        if self.default_strategy:
            return self.default_strategy.ports

        allports = []
        for driver in self.strategy_map.values():
            fw_ports = driver.ports
            if fw_ports:
                allports.append(fw_ports)
        return allports

    @contextlib.contextmanager
    def defer_apply(self):
        """Create a deferred apply context

           This method is not port-based, and therefore must
           be invoked for all strategies. If the default is
           set, then use that instead
        """
        if self.default_strategy:
            self.default_strategy.defer_apply()
            return

        for driver in self.strategy_map.values():
            driver.defer_apply()

    def update_security_group_members(self, sg_id, ips):
        """Update security group memebers

           This method is not port-based, and therefore must
           be invoked for all strategies. If the default is
           set, then use that instead
        """
        if self.default_strategy:
            self.default_strategy.update_security_group_members(sg_id, ips)
            return

        for driver in self.strategy_map.values():
            driver.update_security_group_members(sg_id, ips)

    def update_security_group_rules(self, sg_id, rules):
        """Update security group rules

           This method is not port-based, and therefore must
           be invoked for all strategies. If the default is
           set, then use that instead
        """
        if self.default_strategy:
            self.default_strategy.update_security_group_rules(sg_id, rules)
            return

        for driver in self.strategy_map.values():
            driver.update_security_group_rules(sg_id, rules)
