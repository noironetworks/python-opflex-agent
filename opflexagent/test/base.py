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

from neutron.tests import base


class OpflexTestBase(base.BaseTestCase):

    def setUp(self):
        super(OpflexTestBase, self).setUp()

    def _check_call_list(self, expected, observed, check_all=True):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        if check_all:
            self.assertFalse(
                len(observed),
                msg='There are more calls than expected: %s' % str(observed))

    def _get_gbp_details(self, **kwargs):
        pattern = {'port_id': 'port_id',
                   'mac_address': 'aa:bb:cc:00:11:22',
                   'ptg_id': 'ptg_id',
                   'segmentation_id': None,
                   'network_type': None,
                   'l2_policy_id': 'l2p_id',
                   'l3_policy_id': 'l3p_id',
                   'tenant_id': 'tenant_id',
                   'host': 'host1',
                   'app_profile_name': 'profile_name',
                   'ptg_tenant': 'apic_tenant',
                   'endpoint_group_name': 'epg_name',
                   'promiscuous_mode': False,
                   'vm-name': 'somename',
                   'extra_ips': ['192.169.8.1', '192.169.8.253',
                                 '192.169.8.254'],
                   'vrf_name': 'name_of_l3p',
                   'vrf_tenant': 'apic_tenant',
                   'vrf_subnets': ['192.168.0.0/16', '192.169.0.0/16'],
                   'floating_ip': [{'id': '1',
                                    'floating_ip_address': '172.10.0.1',
                                    'floating_network_id': 'ext_net',
                                    'router_id': 'ext_rout',
                                    'port_id': 'port_id',
                                    'fixed_ip_address': '192.168.0.2',
                                    'nat_epg_tenant': 'nat-epg-tenant',
                                    'nat_epg_name': 'nat-epg-name'},
                                   {'id': '2',
                                    'floating_ip_address': '172.10.0.2',
                                    'floating_network_id': 'ext_net',
                                    'router_id': 'ext_rout',
                                    'port_id': 'port_id',
                                    'fixed_ip_address': '192.168.1.2',
                                    'nat_epg_name': 'nat-epg-name',
                                    'nat_epg_tenant': 'nat-epg-tenant'},
                                   # FIP pointing to one extra-ip
                                   {'id': '7',
                                    'floating_ip_address': '172.10.0.7',
                                    'floating_network_id': 'ext_net',
                                    'router_id': 'ext_rout',
                                    'port_id': 'port_id',
                                    'fixed_ip_address': '192.169.8.1',
                                    'nat_epg_tenant': 'nat-epg-tenant',
                                    'nat_epg_name': 'nat-epg-name'}],
                   'ip_mapping': [{'external_segment_name': 'EXT-1',
                                   'nat_epg_tenant': 'nat-epg-tenant',
                                   'nat_epg_name': 'nat-epg-name'}],
                   'host_snat_ips': [{'external_segment_name': 'EXT-1',
                                      'host_snat_ip': '200.0.0.10',
                                      'gateway_ip': '200.0.0.1',
                                      'prefixlen': 8}],
                   'owned_addresses': ['192.168.0.2'],
                   'attestation': [{
                       'name': 'some_name',
                       'validator': 'base64string', 'mac': 'mac',
                   }],
                   'enable_metadata_optimization': True,
                   }
        pattern.update(**kwargs)
        return pattern
