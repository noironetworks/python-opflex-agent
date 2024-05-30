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


import hashlib

import netaddr
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from oslo_config import cfg
from oslo_log import log as logging

from opflexagent import as_metadata_manager

LOG = logging.getLogger(__name__)


class SnatIptablesManager(object):
    IFACE_PREFIX = 'of-'

    def __init__(self, bridge_manager):
        self.bridge_manager = bridge_manager
        self.snat_conn_track_handler = (
            as_metadata_manager.SnatConnTrackHandler())

    def _cleanup(self, if_name, ns_name):
        self.bridge_manager.delete_port(if_name)
        ip_wrapper_root = ip_lib.IPWrapper()
        if ip_wrapper_root.netns.exists(ns_name):
            # This will in turn shut down conn_track process thru supervisord
            if cfg.CONF.OPFLEX.enable_snat_conn_track:
                self.snat_conn_track_handler.conn_track_del(ns_name)
            ip_wrapper_root.netns.delete(ns_name)

    def _add_port_and_netns(self, if_name, ns_name, if_mac=None, mtu=None):
        self.bridge_manager.add_port(if_name, ('type', 'internal'))
        ip_wrapper_root = ip_lib.IPWrapper()
        if_dev = ip_wrapper_root.device(if_name)
        if if_mac:
            if_dev.link.set_address(if_mac)

        ip_wrapper = ip_wrapper_root.netns.add(ns_name)
        ip_wrapper.netns.execute(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        ip_wrapper.netns.execute(['sysctl', '-w',
                                  'net.ipv4.conf.all.send_redirects=0'])
        ip_wrapper.netns.execute(['sysctl', '-w',
                                  'net.ipv6.conf.all.forwarding=1'])

        if_dev.link.set_netns(ns_name)
        if mtu:
            if_dev.link.set_mtu(mtu)
        if_dev.link.set_up()

        # This will in turn launch the conn_track process thru supervisord
        if cfg.CONF.OPFLEX.enable_snat_conn_track:
            self.snat_conn_track_handler.conn_track_create(ns_name)
        return if_dev

    def _setup_routes(self, if_dev, ver, ip_start, ip_end, gw_ip):
        gw_ip_net = netaddr.IPNetwork(gw_ip)
        if_dev.addr.add("%s/%s" % (ip_start, gw_ip_net.prefixlen))
        if_dev.route.add_gateway(str(gw_ip_net.ip))
        if ip_start != ip_end:
            local_nets = netaddr.cidr_merge(netaddr.iter_iprange(ip_start,
                                                                 ip_end))
            max_pfx_len = (ver == 4 and 32 or 128)
            for l in local_nets:
                if l.prefixlen < max_pfx_len or str(l.ip) != ip_start:
                    if_dev.route._as_root('add', 'local', str(l),
                                          'dev', if_dev.name, options=[ver])

    def _setup_iptables(self, netns, if_name, ip_start, ip_end,
                        ip6_start, ip6_end):
        iptables = iptables_manager.IptablesManager(use_ipv6=True,
                                                    namespace=netns)
        use_v4 = bool(ip_start and ip_end)
        use_v6 = bool(ip6_start and ip6_end)
        ip_versions = []
        if use_v4:
            ip_versions.append((iptables.ipv4, ip_start, ip_end))
        if use_v6:
            ip_versions.append((iptables.ipv6, ip6_start, ip6_end))

        for ipv in ip_versions:
            ver, start, end = ipv
            ver.clear()       # remove default rules created by IptablesManager
            ver['filter'] = iptables_manager.IptablesTable()
            ver['nat'] = iptables_manager.IptablesTable()
            ver['filter'].add_rule('INPUT', '-j ACCEPT', wrap=False)
            ver['filter'].add_rule('FORWARD', '-j ACCEPT', wrap=False)
            ver['nat'].add_rule(
                'POSTROUTING', '-o %s -j SNAT --to-source %s-%s' %
                (if_name, start, end),
                wrap=False)
        if use_v4:
            iptables.ipv4['filter'].add_rule('OUTPUT', '-j ACCEPT', wrap=False)
        if use_v6:
            iptables.ipv6['filter'].add_rule('OUTPUT',
                '-p icmpv6 --icmpv6-type redirect -j DROP', wrap=False)
            iptables.ipv6['filter'].add_rule('OUTPUT', '-j ACCEPT', wrap=False)
        iptables.apply()

    def _get_hash_for_es(self, es_name):
        return ("%s%s" % (self.IFACE_PREFIX,
            hashlib.md5(es_name.encode('utf-8')).hexdigest()[:12]))  # nosec

    def setup_snat_for_es(self, es_name,
                          ip_start=None, ip_end=None, ip_gw=None,
                          ip6_start=None, ip6_end=None, ip6_gw=None,
                          next_hop_mac=None, mtu=None):
        next_hop_if = self._get_hash_for_es(es_name)
        ns = next_hop_if

        use_v4 = bool(ip_start and ip_gw)
        use_v6 = bool(ip6_start and ip6_gw)

        if not use_v4 and not use_v6:
            return (None, next_hop_mac)

        ip_end = ip_end or ip_start
        ip6_end = ip6_end or ip6_start

        self._cleanup(next_hop_if, ns)
        if_dev = self._add_port_and_netns(next_hop_if, ns,
                                          if_mac=next_hop_mac, mtu=mtu)
        next_hop_mac = if_dev.link.address
        LOG.debug("Created namespace %(ns)s, and added port %(pt)s to it",
                  {'ns': ns, 'pt': next_hop_if})

        if use_v4:
            self._setup_routes(if_dev, 4, ip_start, ip_end, ip_gw)
            LOG.debug("Set IPv4 address and routes")

        if use_v6:
            self._setup_routes(if_dev, 6, ip6_start, ip6_end, ip6_gw)
            LOG.debug("Set IPv6 address and routes")

        self._setup_iptables(ns, next_hop_if, ip_start, ip_end,
                             ip6_start, ip6_end)
        LOG.debug("Installed iptables rules")
        return (next_hop_if, next_hop_mac)

    def cleanup_snat_for_es(self, es_name, next_hop_if=None):
        next_hop_if = next_hop_if or self._get_hash_for_es(es_name)
        self._cleanup(next_hop_if, next_hop_if)

    def cleanup_snat_all(self, exclude_es=[]):
        exclude_ports = set([self._get_hash_for_es(e) for e in exclude_es])
        ports = [p for p in self.bridge_manager.get_port_name_list()
                 if p.startswith(self.IFACE_PREFIX) and p not in exclude_ports]
        for ifn in ports:
            self._cleanup(ifn, ifn)

    def check_if_exists(self, es_name):
        ns_name = self._get_hash_for_es(es_name)
        return ip_lib.IPWrapper().netns.exists(ns_name)
