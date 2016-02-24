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
import mock

from opflexagent import gbp_ovs_agent

from neutron.agent.dhcp import config as dhcp_config
from neutron.agent import firewall
from neutron.tests import base
from oslo_config import cfg
from oslo_utils import uuidutils

_uuid = uuidutils.generate_uuid
EP_DIR = '.%s_endpoints/'
TENANTID1 = "footenant"
NETID1 = "foonet1"
SUBNETID1 = "foosubnet1"
SECGROUP1 = "foosecgroup1"
SECGROUP2 = "foosecgroup2"
port1 = ({"status": "DOWN",
          "name": "private-port",
          "allowed_address_pairs": [],
          "admin_state_up": True,
          "network_id": NETID1,
          "tenant_id": TENANTID1,
          "device_owner": "",
          "mac_address": "fa:16:3e:c9:cb:f0",
          "binding:vif_details": {
              "port_filter": True,
              "dvs_port_group": "bar"
          },
          "binding:vnic_type": "normal",
          "binding:vif_type": "unbound",
          "fixed_ips": [{
              "subnet_id": SUBNETID1,
              "ip_address": "10.0.0.2"}
          ],
          "id": "fooid1",
          "security_groups": [SECGROUP1],
          "device_id": ""})

port2 = ({"status": "DOWN",
          "binding:host_id": "",
          "allowed_address_pairs": [],
          "extra_dhcp_opts": [],
          "device_owner": "",
          "binding:profile": {},
          "fixed_ips": [{
              "subnet_id": SUBNETID1,
              "ip_address": "10.0.0.3"}
          ],
          "id": "fooid2",
          "security_groups": [SECGROUP2],
          "device_id": "",
          "name": "pt_esx_vm1_gbpui",
          "admin_state_up": True,
          "network_id": NETID1,
          "tenant_id": TENANTID1,
          "binding:vif_details": {
              "port_filter": True,
              "foo_key": "bar"
          },
          "binding:vnic_type": "normal",
          "binding:vif_type": "unbound",
          "mac_address": "fa:16:3e:db:e9:0e"})

sg_id1 = "foosecuritygroup"
sg_rule1 = {"foo_rule1": "rule"}
sg_members1 = ["foomember1", "foomember2"]


class FakeFw1(firewall.FirewallDriver):
    def prepare_port_filter(self, port):
        pass

    def apply_port_filter(self, port):
        pass

    def update_port_filter(self, port):
        pass

    def remove_port_filter(self, port):
        pass

    @property
    def ports(self):
        return None

    def update_security_group_rules(self, sg_id, sg_rules):
        pass

    def update_security_group_members(self, sg_id, sg_members):
        pass

    def filter_defer_apply_on(self):
        pass

    def filter_defer_apply_off(self):
        pass


class FakeFw2(FakeFw1):
    def __init__(self):
        pass


class FakeFw3(FakeFw1):
    def __init__(self):
        pass


class TestFirewallWrapperBase(base.BaseTestCase):
    """Base class for firewall tests

       This is a base class for firewall wrapper testing.
       It doesn't implement any tests itself, but provides
       the common functionality needed by derived classes.
    """
    def setUp(self):
        super(TestFirewallWrapperBase, self).setUp()
        self.agent = self._initialize_agent()

    def _initialize_agent_config(self):
        """Config file initialization -- specialize as needed"""
        cfg.CONF.register_opts(dhcp_config.DHCP_OPTS)
        cfg.CONF.set_override('firewall_map',
            [('dvs_port_key',
            'opflexagent.test.test_fw_wrapper.FakeFw1'),
             ('foo_key',
            'opflexagent.test.test_fw_wrapper.FakeFw2'), ], 'OPFLEX')
        cfg.CONF.set_default('firewall_driver',
                             'opflexagent.test.test_fw_wrapper.FakeFw3',
                             group='SECURITYGROUP')

    def _initialize_agent(self):
        self._initialize_agent_config()

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        with contextlib.nested(
            mock.patch('opflexagent.utils.ep_managers.endpoint_file_manager'
                       '.EndpointFileManager'),
            mock.patch('opflexagent.opflex_notify.OpflexNotifyAgent',
                       return_value=mock.Mock()),
            mock.patch('opflexagent.utils.bridge_managers.ovs_manager.'
                       'OvsManager.setup_integration_bridge',
                       return_value=mock.Mock()),
            mock.patch('neutron.agent.common.ovs_lib.OVSBridge.'
                       'create'),
            mock.patch('neutron.agent.common.ovs_lib.OVSBridge.'
                       'set_secure_mode'),
            mock.patch('neutron.agent.common.ovs_lib.OVSBridge.'
                       'get_local_port_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.common.ovs_lib.BaseOVS.get_bridges'),
            mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall),
            mock.patch('opflexagent.gbp_ovs_agent.GBPOpflexAgent.'
                       '_report_state')):
                kwargs = gbp_ovs_agent.create_agent_config_map(cfg.CONF)
                agent = gbp_ovs_agent.GBPOpflexAgent(**kwargs)
            # set back to true because initial report state will succeed due
            # to mocked out RPC calls
        agent.use_call = True
        agent.tun_br = mock.Mock()
        agent.ep_manager = mock.Mock()
        agent.bridge_manager = mock.Mock()
        agent.of_rpc.get_gbp_details = mock.Mock()
        agent.notify_worker.terminate()
        return agent


class TestFirewallWrapper(TestFirewallWrapperBase):
    """Test basic firewall wrapper functionality

       This tests the basic firewall wrapper functions.
       It does not test the decorators of the mocked
       classes.
    """
    def setUp(self):
        self.fw1 = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw1').start()()
        self.fw2 = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw2').start()()
        self.fw3 = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw3').start()()

        self.strategy_fn = mock.patch(
            'opflexagent.gbp_ovs_agent.strategy_fn').start()
        super(TestFirewallWrapper, self).setUp()

    def test_fw_wrapper_normal_strategy_key1(self):
        """Test non-decorator-based strategy methods

           Test the firewall wrapper class' strategy
           methods that use port-based keying. This
           verifies the first key in the map.
        """
        self.strategy_fn.return_value = 'dvs_port_key'
        self.agent.sg_agent.firewall.prepare_port_filter(port1)
        self.fw1.prepare_port_filter.assert_called_once_with(port1)
        self.fw2.prepare_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.apply_port_filter(port1)
        self.fw1.apply_port_filter.assert_called_once_with(port1)
        self.fw2.apply_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.update_port_filter(port1)
        self.fw1.update_port_filter.assert_called_once_with(port1)
        self.fw2.update_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.remove_port_filter(port1)
        self.fw1.remove_port_filter.assert_called_once_with(port1)
        self.fw2.remove_port_filter.assert_not_called()

        self.agent.sg_agent.firewall.update_security_group_rules(
            sg_id1, sg_rule1)
        self.fw1.update_security_group_rules.assert_called_once_with(
            sg_id1, sg_rule1)
        self.fw2.update_security_group_rules.assert_called_once_with(
            sg_id1, sg_rule1)
        self.agent.sg_agent.firewall.update_security_group_members(
            sg_id1, sg_members1)
        self.fw1.update_security_group_members.assert_called_once_with(
            sg_id1, sg_members1)
        self.fw2.update_security_group_members.assert_called_once_with(
            sg_id1, sg_members1)
        self.agent.sg_agent.firewall.filter_defer_apply_on()
        self.fw1.filter_defer_apply_on.assert_called_once_with()
        self.fw2.filter_defer_apply_on.assert_called_once_with()
        self.agent.sg_agent.firewall.filter_defer_apply_off()
        self.fw1.filter_defer_apply_off.assert_called_once_with()
        self.fw2.filter_defer_apply_off.assert_called_once_with()

    def test_fw_wrapper_normal_strategy_key2(self):
        """Test non-decorator-based strategy methods

           Test the firewall wrapper class' strategy
           methods that use port-based keying. This
           verifies the second key in the map.
        """
        self.strategy_fn.return_value = 'foo_key'
        self.agent.sg_agent.firewall.prepare_port_filter(port2)
        self.fw2.prepare_port_filter.assert_called_once_with(port2)
        self.fw1.prepare_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.apply_port_filter(port2)
        self.fw2.apply_port_filter.assert_called_once_with(port2)
        self.fw1.apply_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.update_port_filter(port2)
        self.fw2.update_port_filter.assert_called_once_with(port2)
        self.fw1.update_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.remove_port_filter(port2)
        self.fw2.remove_port_filter.assert_called_once_with(port2)
        self.fw1.remove_port_filter.assert_not_called()

        self.agent.sg_agent.firewall.update_security_group_rules(
            sg_id1, sg_rule1)
        self.fw2.update_security_group_rules.assert_called_once_with(
            sg_id1, sg_rule1)
        self.fw1.update_security_group_rules.assert_called_once_with(
            sg_id1, sg_rule1)
        self.agent.sg_agent.firewall.update_security_group_members(
            sg_id1, sg_members1)
        self.fw2.update_security_group_members.assert_called_once_with(
            sg_id1, sg_members1)
        self.fw1.update_security_group_members.assert_called_once_with(
            sg_id1, sg_members1)
        self.agent.sg_agent.firewall.filter_defer_apply_on()
        self.fw2.filter_defer_apply_on.assert_called_once_with()
        self.fw1.filter_defer_apply_on.assert_called_once_with()
        self.agent.sg_agent.firewall.filter_defer_apply_off()
        self.fw2.filter_defer_apply_off.assert_called_once_with()
        self.fw1.filter_defer_apply_off.assert_called_once_with()


class TestFirewallWrapperDefault(TestFirewallWrapperBase):
    """Test default firewall wrapper functionality

       This tests the default firewall wrapper functions.
       It does not test the decorators of the mocked
       classes.
    """
    def setUp(self):
        self.fw1 = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw1').start()()
        self.fw2 = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw2').start()()
        self.fw3 = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw3').start()()

        self.strategy_fn = mock.patch(
            'opflexagent.gbp_ovs_agent.strategy_fn').start()
        super(TestFirewallWrapperDefault, self).setUp()

    def _initialize_agent_config(self):
        cfg.CONF.register_opts(dhcp_config.DHCP_OPTS)
        cfg.CONF.set_override('firewall_map', [], 'OPFLEX')
        cfg.CONF.set_default('firewall_driver',
                             'opflexagent.test.test_fw_wrapper.FakeFw3',
                             group='SECURITYGROUP')

    def test_fw_wrapper_default_strategy(self):
        """Test non-decorator-based strategy methods

           Test the firewall wrapper class' strategy
           methods that use port-based keying. This
           verifies the second key in the map.
        """
        self.strategy_fn.return_value = None
        self.agent.sg_agent.firewall.prepare_port_filter(port2)
        self.fw3.prepare_port_filter.assert_called_once_with(port2)
        self.fw1.prepare_port_filter.assert_not_called()
        self.fw2.prepare_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.apply_port_filter(port2)
        self.fw3.apply_port_filter.assert_called_once_with(port2)
        self.fw1.apply_port_filter.assert_not_called()
        self.fw2.apply_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.update_port_filter(port2)
        self.fw3.update_port_filter.assert_called_once_with(port2)
        self.fw1.update_port_filter.assert_not_called()
        self.fw2.update_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.remove_port_filter(port2)
        self.fw3.remove_port_filter.assert_called_once_with(port2)
        self.fw1.remove_port_filter.assert_not_called()
        self.fw2.remove_port_filter.assert_not_called()
        self.agent.sg_agent.firewall.update_security_group_rules(
            sg_id1, sg_rule1)
        self.fw3.update_security_group_rules.assert_called_once_with(
            sg_id1, sg_rule1)
        self.fw1.update_security_group_rules.assert_not_called()
        self.fw2.update_security_group_rules.assert_not_called()
        self.agent.sg_agent.firewall.update_security_group_members(
            sg_id1, sg_members1)
        self.fw3.update_security_group_members.assert_called_once_with(
            sg_id1, sg_members1)
        self.fw1.update_security_group_members.not_called()
        self.fw2.update_security_group_members.not_called()
        self.agent.sg_agent.firewall.filter_defer_apply_on()
        self.fw3.filter_defer_apply_on.assert_called_once_with()
        self.fw1.filter_defer_apply_on.assert_not_called()
        self.fw2.filter_defer_apply_on.assert_not_called()
        self.agent.sg_agent.firewall.filter_defer_apply_off()
        self.fw3.filter_defer_apply_off.assert_called_once_with()
        self.fw1.filter_defer_apply_off.assert_not_called()
        self.fw2.filter_defer_apply_off.assert_not_called()


class TestFirewallWrapperDecorators(TestFirewallWrapperBase):

    def setUp(self):
        self.fw1ports = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw1.ports').start()()
        self.fw1defer = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw1.defer_apply').start()()
        self.fw2ports = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw2.ports').start()()
        self.fw2defer = mock.patch(
            'opflexagent.test.test_fw_wrapper.FakeFw2.defer_apply').start()()

        self.strategy_fn = mock.patch(
            'opflexagent.gbp_ovs_agent.strategy_fn').start()
        super(TestFirewallWrapperDecorators, self).setUp()

    #TODO(tbachman) Figure out how to properly test decorators
    def _test_fw_wrapper_decorator_strategy_key1(self):
        self.strategy_fn.return_value = None
        self.agent.sg_agent.firewall.ports
        self.fw1ports.assert_called_once_with()
        self.fw2ports.assert_called_once_with()

        self.agent.sg_agent.firewall.defer_apply()
        self.fw1defer.assert_called_once_with()
        self.fw2defer.assert_called_once_with()
