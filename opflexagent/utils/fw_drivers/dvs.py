# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from neutron.agent import firewall
from oslo_log import log as logging

#from vmware_dvs.common import config
#from vmware_dvs.utils import security_group_utils as sg_util
#from vmware_dvs.utils import dvs_util

LOG = logging.getLogger(__name__)

#CONF = config.CONF


class DVSFirewallDriver(firewall.FirewallDriver):
    """DVS Firewall Driver.
    """
    def __init__(self):
        pass

    def prepare_port_filter(self, port):
        LOG.info(_("Applied security group rules for port %s"), port['id'])

    def apply_port_filter(self, port):
        pass

    def update_port_filter(self, port):
        LOG.info(_("Updated security group rules for port %s"), port['id'])

    def remove_port_filter(self, port):
        pass

    @property
    def ports(self):
        return self.dvs_ports

    def update_security_group_rules(self, sg_id, sg_rules):
        LOG.debug("Update rules of security group (%s)", sg_id)

    def update_security_group_members(self, sg_id, sg_members):
        LOG.debug("Update members of security group (%s)", sg_id)

    def filter_defer_apply_on(self):
        pass

    def filter_defer_apply_off(self):
        pass
