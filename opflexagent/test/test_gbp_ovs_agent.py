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

import shutil
import sys

import mock
sys.modules["apicapi"] = mock.Mock()

import contextlib
from opflexagent import gbp_ovs_agent

from neutron.openstack.common import uuidutils
from neutron.tests import base
from oslo.config import cfg

_uuid = uuidutils.generate_uuid
NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'
EP_DIR = '.%s_endpoints/'


class TestGbpOvsAgent(base.BaseTestCase):

    def setUp(self):
        super(TestGbpOvsAgent, self).setUp()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        cfg.CONF.set_default('quitting_rpc_timeout', 10, 'AGENT')
        self.ep_dir = EP_DIR % _uuid()
        self.agent = self._initialize_agent()
        self.agent._write_endpoint_file = mock.Mock()
        self.agent.mapping_cleanup = mock.Mock()
        self.agent.opflex_networks = ['phys_net']
        self.addCleanup(self._purge_endpoint_dir)

    def _purge_endpoint_dir(self):
        try:
            shutil.rmtree(self.ep_dir)
        except OSError:
            pass

    def _initialize_agent(self):
        cfg.CONF.set_override('epg_mapping_dir', self.ep_dir, 'OPFLEX')
        kwargs = gbp_ovs_agent.create_agent_config_map(cfg.CONF)

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        with contextlib.nested(
            mock.patch('opflexagent.gbp_ovs_agent.GBPOvsAgent.'
                       'setup_integration_br',
                       return_value=mock.Mock()),
            mock.patch('opflexagent.gbp_ovs_agent.GBPOvsAgent.'
                       'setup_ancillary_bridges',
                       return_value=[]),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'create'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'set_secure_mode'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'get_local_port_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.ovs_lib.BaseOVS.get_bridges'),
            mock.patch('neutron.openstack.common.loopingcall.'
                       'FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall),
            mock.patch('neutron.plugins.openvswitch.agent.ovs_neutron_agent.'
                       'OVSNeutronAgent._report_state')):
            agent = gbp_ovs_agent.GBPOvsAgent(**kwargs)
            # set back to true because initial report state will succeed due
            # to mocked out RPC calls
            agent.use_call = True
            agent.tun_br = mock.Mock()
        agent.sg_agent = mock.Mock()
        return agent

    def _get_gbp_details(self, **kwargs):
        pattern = {'port_id': 'port_id',
                   'mac_address': 'aa:bb:cc:00:11:22',
                   'ptg_id': 'ptg_id',
                   'segmentation_id': None,
                   'network_type': None,
                   'l2_policy_id': 'l2p_id',
                   'tenant_id': 'tenant_id',
                   'host': 'host1',
                   'app_profile_name': 'profile_name',
                   'ptg_tenant': 'apic_tenant',
                   'endpoint_group_name': 'epg_name',
                   'promiscuous_mode': False,
                   'vm-name': 'somename',
                   'extra_ips': ['192.169.8.1', '192.169.8.254']}
        pattern.update(**kwargs)
        return pattern

    def _port_bound_args(self, net_type='net_type'):
        return {'port': mock.Mock(),
                'net_uuid': 'net_id',
                'network_type': net_type,
                'physical_network': 'phys_net',
                'segmentation_id': 1000,
                'fixed_ips': [{'subnet_id': 'id1',
                               'ip_address': '192.168.0.2'},
                              {'subnet_id': 'id2',
                               'ip_address': '192.168.1.2'}],
                'device_owner': 'compute:',
                'ovs_restarted': True}

    def test_port_bound(self):
        self.agent.int_br = mock.Mock()
        self.agent.of_rpc.get_gbp_details = mock.Mock()
        mapping = self._get_gbp_details()
        self.agent.of_rpc.get_gbp_details.return_value = mapping
        self.agent.provision_local_vlan = mock.Mock()
        args = self._port_bound_args('opflex')
        args['port'].gbp_details = mapping
        self.agent.port_bound(**args)
        self.agent.int_br.clear_db_attribute.assert_called_with(
            "Port", mock.ANY, "tag")
        self.assertFalse(self.agent.provision_local_vlan.called)
        self.agent._write_endpoint_file.assert_called_with(
            args['port'].vif_id, {
                "policy-space-name": mapping['ptg_tenant'],
                "endpoint-group-name": (mapping['app_profile_name'] + "|" +
                                        mapping['endpoint_group_name']),
                "interface-name": args['port'].port_name,
                "mac": args['port'].vif_mac,
                "promiscuous-mode": mapping['promiscuous_mode'],
                "uuid": args['port'].vif_id,
                "attributes": {'vm-name': 'somename'},
                "ip": ['192.168.0.2', '192.168.1.2', '192.169.8.1',
                       '192.169.8.254']})

    def test_port_bound_no_mapping(self):
        self.agent.int_br = mock.Mock()
        self.agent.of_rpc.get_gbp_details = mock.Mock()
        self.agent.of_rpc.get_gbp_details.return_value = None
        self.agent.provision_local_vlan = mock.Mock()
        args = self._port_bound_args('opflex')
        args['port'].gbp_details = None
        self.agent.port_bound(**args)
        self.assertFalse(self.agent.int_br.set_db_attribute.called)
        self.assertFalse(self.agent.provision_local_vlan.called)
        self.assertFalse(self.agent._write_endpoint_file.called)
