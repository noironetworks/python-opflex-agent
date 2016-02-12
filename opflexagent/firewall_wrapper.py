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

from oslo_log import log as logging
from oslo_utils import importutils


LOG = logging.getLogger(__name__)


class FirewallDriverWrapper(object):
    """Wrapper for Firewall Driver implemntations

    This wrapper class keeps a map of drivers to use for
    implementing a firewall driver. The firewall driver methods
    are divided into two groups:
      1) methods where only one driver implementation should be called
      2) methods where all driver implementations should be called

    The first group is called when there is only a single argument:
    the neutron port. The second group is called in all other cases.
    The first group uses a key to determine which driver gets invoked.
    The key is obtained by a user-defined strategy function, which gets
    passed the port object. The strategy function is meant to perform
    some operation (e.g. search) on the port to determine and return
    the key to use for looking up the appropriate firewall driver.

    There is also a defaulit firewall driver. This is used when there
    is only a single firewall driver is used, and therefore a key is
    not needed.
    """

    def __init__(self):
        self._strategy_map = {}
        self._strategy_fn = None
        self._default_strategy = None
        self._port_methods = ['prepare_port_filter',
                              'apply_port_filter',
                              'update_port_filter',
                              'remove_port_filter']
        self._all_strategy_methods = ['filter_defer_apply_on',
                                      'filter_defer_apply_off',
                                      'ports',
                                      'defer_apply',
                                      'update_security_group_members',
                                      'update_security_group_rules']

    def _do_port_strategy(self, name, port, *p_args, **p_kwargs):
        """Call a single firewall driver method"""
        strategy_obj = self._default_strategy
        if self._strategy_map and self._strategy_fn:
            key = self._strategy_fn(port, self._strategy_map)
            if key:
                strategy_obj = self._strategy_map[key]
        return getattr(strategy_obj, name)(port)

    def _do_all_strategy(self, name, *s_args, **s_kwargs):
        """Call all the firewall driver methods"""
        if self._default_strategy:
            return getattr(self._default_strategy, name)(*s_args, **s_kwargs)
        else:
            ret_list = []
            for driver in self._strategy_map.values():
                ret_list.append(getattr(driver, name)(*s_args, **s_kwargs))
            return ret_list

    def __getattr__(self, name):
        def _do_strategy(*args, **kwargs):
            """Invoke the appropiate strategy method

            This checks whether the method is in the port-based
            methods or non-port-based methods, and invokes the
            appropriate strategy. If it's not a valid method,
            it raises AttributeError
            """
            if name in self._port_methods:
                return self._do_port_strategy(name, *args, **kwargs)
            elif name in self._all_strategy_methods:
                return self._do_all_strategy(name, *args, **kwargs)
            else:
                raise AttributeError
        return _do_strategy

    def set_strategy_and_map(self, strategy_map, strategy_fn, default):
        """Set Firewall Driver strategy and map

           This sets the strategy to call when selecting
           which firewall driver to use. It also provides
           a list of tuples, which are turned into a map
           of security group objects/implementations, indexed
           by their keys.
        """
        if not strategy_map and default is None:
            return

        # set default strategy if a map wasn't provided
        if not strategy_map:
            self._default_strategy = importutils.import_object(default)

        self._strategy_fn = strategy_fn

        # We need to go through and load each of the classes
        # in the firewall map and provide that in our map
        for element in strategy_map:
            key, value = element
            self._strategy_map[key] = importutils.import_object(value)
