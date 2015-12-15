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

from oslo_config import cfg


gbp_opts = [
    cfg.BoolOpt('hybrid_mode',
                default=False,
                help=_("Whether Neutron's ports can coexist with GBP owned"
                       "ports.")),
    cfg.StrOpt('epg_mapping_dir',
               default='/var/lib/opflex-agent-ovs/endpoints/',
               help=_("Directory where the EPG port mappings will be "
                      "stored.")),
    cfg.StrOpt('as_mapping_dir',
               default='/var/lib/opflex-agent-ovs/services/',
               help=_("Directory where the anycast svc mappings will be "
                      "stored.")),
    cfg.StrOpt('opflex_agent_dir',
               default='/var/lib/neutron/opflex_agent',
               help=_("Directory where the opflex agent state will be "
                      "stored.")),
    cfg.ListOpt('opflex_networks',
                default=['*'],
                help=_("List of the physical networks managed by this agent. "
                       "Use * for binding any opflex network to this agent")),
    cfg.ListOpt('internal_floating_ip_pool',
               default=['169.254.0.0/16'],
               help=_("IP pool used for intermediate floating-IPs with SNAT")),
    cfg.ListOpt('internal_floating_ip6_pool',
               default=['fe80::/64'],
               help=_("IPv6 pool used for intermediate floating-IPs "
                      "with SNAT"))
]

cfg.CONF.register_opts(gbp_opts, "OPFLEX")
