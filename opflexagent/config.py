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
    cfg.ListOpt('vlan_networks',
                default=['*'],
                help=_("List of the physical networks managed by this agent. "
                       "Use * for binding any vlan network to this agent")),
    cfg.ListOpt('internal_floating_ip_pool',
               default=['169.254.0.0/16'],
               help=_("IP pool used for intermediate floating-IPs with SNAT")),
    cfg.ListOpt('internal_floating_ip6_pool',
               default=['fe80::/64'],
               help=_("IPv6 pool used for intermediate floating-IPs "
                      "with SNAT")),
    cfg.IntOpt('endpoint_request_timeout', default=300,
               help=_("Value in seconds that defines after how long the agent "
                      "should reschedule port info on missing response.")),
    cfg.FloatOpt('config_apply_interval', default=0.5,
                 help=_("Value in seconds (fraction of a second is allowed "
                        "as well) that defines how often the agent checks for "
                        "RPC responses and applies them if any were received "
                        "while in idle.")),
    cfg.StrOpt('agent_mode',
               default='opflex',
               help=_("Set the mode of the agent to be used. Options are: "
                      "'opflex' (default), 'dvs', and 'dvs_no_binding'.")),
    cfg.StrOpt('opflex_notify_socket_path',
               default='/var/run/opflex-agent-notif.sock',
               help=_("Path of the Opflex notification socket.")),
    cfg.IntOpt('nat_mtu_size', default=0,
               help=_("MTU size of the NAT namespace interface.")),
    cfg.StrOpt('fabric_bridge', default='br-fabric',
               help=_("The name of the bridge which connects to the ACI "
                      "fabric")),
    cfg.StrOpt('nested_domain_uplink_interface', default='patch-fab-ex',
               help=_("This is used in the nested Kubernetes configuration "
                      "to denote the name of the OVS interface that serves "
                      "as the uplink for the host. On RHEL installation, "
                      "this corresponds to the patch port on br-fabric that "
                      "connects to br-ex")),
    cfg.StrOpt('bridge_manager',
               default='ovs',
               help=_("The class to use for OVS bridge management. "
                      "Options are: 'ovs' (default), 'vpp' and 'fake'.")),
    cfg.StrOpt('conn_track_syslog_facility', default='user',
               help=_("The syslog facility used by opflex-conn-track "
                      "program")),
    cfg.StrOpt('conn_track_syslog_severity', default='info',
               help=_("The syslog severity used by opflex-conn-track "
                      "program")),
    cfg.BoolOpt('enable_snat_conn_track', default=True,
                help=("Enable the SNAT connection track which will dump "
                      "the output to syslog.")),
    cfg.BoolOpt('disable_security_group_for_nested_mode', default=False,
                help=("Disable the security group configuration for ports "
                      "created under nested mode networks.")),
]

vpp_opts = [
    cfg.StrOpt('vhostuser_socket_dir', default='/var/run/vpp-sockets',
               help=_("Path where VPP vhost-user sockets are created by nova"))
]

cfg.CONF.register_opts(gbp_opts, "OPFLEX")
cfg.CONF.register_opts(vpp_opts, "VPP")
