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

import collections

from unittest import mock

from neutron.tests import base

from opflexagent import apic_dhcp


class TestApicDhcp(base.BaseTestCase):

    def test_get_isolated_subnets_defaults_to_true(self):
        isolated = apic_dhcp.ApicDnsmasq.get_isolated_subnets(mock.Mock())

        self.assertIsInstance(isolated, collections.defaultdict)
        self.assertTrue(isolated['subnet-id'])
