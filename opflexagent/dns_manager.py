import collections
import copy
import functools
import subprocess  # nosec
from oslo_config import cfg
import eventlet
import json

from neutron_lib.agent import topics

from opflexagent.Dnsmasq import Dnsmasq
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from oslo_concurrency import lockutils
from oslo_log import log as logging
from oslo_utils import encodeutils

from neutron.agent.dhcp.agent import DhcpPluginApi
from neutron.agent.linux import external_process
from neutron.agent.linux import dhcp
from neutron.common import config as common_config
from neutron.conf.agent import common as config
from neutron.conf.agent import dhcp as dhcp_config
from neutron.conf.agent.metadata import config as meta_conf
from neutron.conf.plugins.ml2.drivers import ovs_conf
from neutron import service as neutron_service
from neutron._i18n import _
from neutron_lib.utils import helpers

INTERFACE_DRIVER_OPTS = [
    cfg.StrOpt('interface_driver',
               default='neutron.agent.linux.interface.OVSInterfaceDriver',
               help=_("The driver used to manage the virtual interface.")),
]

class convert_to_dot_notation(dict):
    """
    Access dictionary attributes via dot notation
    """

    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __deepcopy__(self, memo=None):
        return convert_to_dot_notation(copy.deepcopy(dict(self), memo=memo))


class DnsManager(object):
    def register_options(self, conf):
        config.register_agent_state_opts_helper(conf)
        config.register_availability_zone_opts_helper(conf)
        dhcp_config.register_agent_dhcp_opts(conf)
        meta_conf.register_meta_conf_opts(meta_conf.SHARED_OPTS, conf)
        config.register_interface_opts(conf)
        config.register_root_helper(conf)
        conf.register_opts(INTERFACE_DRIVER_OPTS)


    def __init__(self, logger):
        self.name = "DNSManager"
        self.root_helper = cfg.CONF.AGENT.root_helper
        self.network_cache = {}
        self.subnet_cache = {}
        self.port_cache = {}
        global LOG
        LOG = logger
        self.register_options(cfg.CONF)
        self.dhcp_version = Dnsmasq.check_version()
        registry.register(self.handle_networks, resources.NETWORK)
        registry.register(self.handle_subnets, resources.SUBNET)
        registry.register(self.handle_ports, resources.PORT)
        self.conf = cfg.CONF
        self._process_monitor = external_process.ProcessMonitor(
            config=self.conf,
            resource_type='dhcp')
        self.plugin_rpc = DhcpPluginApi(topics.PLUGIN, self.conf.host)

    def has_ip(self, ipaddr, ns, nsport):
        outp = self.sh("ip netns exec %s ip addr show dev %s" %
                (ns, nsport))
        return 'net %s/' % (ipaddr, ) in outp

    def add_ip(self, ns, ipaddr, nsport):
        if self.has_ip(ipaddr, ns, nsport):
            return
        SVC_IP_CIDR = 16
        self.sh("ip netns exec %s ip addr add %s/%s dev %s" %
                (ns, ipaddr, SVC_IP_CIDR, nsport))

    def add_default_route(self, ns, nexthop):
        self.sh("ip netns exec %s ip route add default via %s" %
                (ns, nexthop))
    
    def sh(self, cmd, as_root=True):
        if as_root and self.root_helper:
            cmd = "%s %s" % (self.root_helper, cmd)
        LOG.debug("%(name)s: Running command: %(cmd)s",
                  {'name': self.name, 'cmd': cmd})
        ret = ''
        try:
            sanitized_cmd = encodeutils.to_utf8(cmd)
            data = subprocess.check_output(
                sanitized_cmd, stderr=subprocess.STDOUT, shell=True)  # nosec
            ret = helpers.safe_decode_utf8(data)
        except Exception as e:
            LOG.error("%(name)s: In running command: %(cmd)s: %(exc)s",
                      {'name': self.name, 'cmd': cmd, 'exc': str(e)})
        LOG.debug("%(name)s: Command output: %(ret)s",
                  {'name': self.name, 'ret': ret})
        return ret


    def build_network(self, net_id):
        if self.network_cache.get(net_id) is None:
            return None
        nwork = self.network_cache[net_id]
        nwork.subnets = self.subnet_cache.get(net_id)
        nwork.ports = self.port_cache.get(net_id)
        return nwork


    def find_index(self, lst, condition):
        return [i for i, elem in enumerate(lst) if condition(elem)]
    
    
    def convert_subnet(self, subnet):
        d = {
            "id": subnet.id,
            "name": subnet.name,
            "tenant_id": subnet.tenant_id,
            "network_id": subnet.network_id,
            "ip_version": subnet.ip_version,
            "subnetpool_id": subnet.subnetpool_id,
            "enable_dhcp": subnet.enable_dhcp,
            "ipv6_ra_mode": subnet.ipv6_ra_mode,
            "ipv6_address_mode": subnet.ipv6_address_mode,
            "gateway_ip": subnet.gateway_ip,
            "cidr": subnet.cidr,
            "allocation_pools": subnet.allocation_pools,
            "host_routes": subnet.host_routes,
            "dns_nameservers": subnet.dns_nameservers,
            "shared": subnet.shared,
            "description": subnet.description,
            "service_types": subnet.service_types,
            "created_at": subnet.created_at,
            "updated_at": subnet.updated_at,
            "revision_number": subnet.revision_number,
            "project_id": subnet.project_id
        }
        return convert_to_dot_notation(d)
    
    def convert_port(self, port):
        d = {
            "device_id": port.device_id,
            "admin_state_up": port.admin_state_up,
            "allowed_address_pairs": port.allowed_address_pairs,
            "binding_levels": port.binding_levels,
            "bindings": port.bindings,
            "data_plane_status": port.data_plane_status,
            "device_owner": port.device_owner,
            "dhcp_options": port.dhcp_options,
            "distributed_bindings": port.distributed_bindings,
            "dns": port.dns,
            "fixed_ips": port.fixed_ips,
            "id": port.id,
            "mac_address": port.mac_address,
            "network_id": port.network_id,
            "project_id": port.project_id,
            "qos_network_policy_id": port.qos_network_policy_id,
            "qos_policy_id": port.qos_policy_id,
            "revision_number": port.revision_number,
            "security": port.security,
            "security_group_ids": port.security_group_ids,
            "status": port.status,
            "updated_at": port.updated_at
        }
        return convert_to_dot_notation(d)

    def handle_subnets(self, ctx, resource_type, subnets, event_type):
        LOG.debug('DNSMANAGER SUBNET EVENT %s for %s of type %s' % (resource_type, subnets, event_type))
        subnet = subnets[0]
        subnet_net_id = subnet.network_id
        if self.subnet_cache.get(subnet_net_id) is None:
            self.subnet_cache[subnet_net_id] = []

        if "id" in subnet:
            currentIndex = self.find_index(self.subnet_cache[subnet_net_id], lambda e: e.id == subnet.id)
            if len(currentIndex) == 0:
                self.subnet_cache[subnet_net_id].append(self.convert_subnet(subnet))
            else:
                self.subnet_cache[subnet_net_id][currentIndex[0]] = self.convert_subnet(subnet)
                self.subnet_cache[subnet_net_id].sort(key=lambda x: x.id)

        if "updated" in str(event_type):
            self.call_driver(self.build_network(subnet_net_id),  str(event_type))


    def handle_ports(self, ctx, resource_type, ports, event_type):
        port = ports[0]
        if "network_id" not in port:
            return
        LOG.debug('DNSMANAGER PORT EVENT %s for %s of type %s' % (resource_type, ports, event_type))
        port_net_id = port.network_id
        if self.port_cache.get(port_net_id) is None:
            self.port_cache[port_net_id] = []      
        
        if "id" in port:
            currentIndex = self.find_index(self.port_cache[port_net_id], lambda e: e.id == port.id)
            if len(currentIndex) == 0:
                self.port_cache[port_net_id].append(self.convert_port(port))
            else:
                self.port_cache[port_net_id][currentIndex[0]] = self.convert_port(port)
                self.port_cache[port_net_id].sort(key=lambda x: x.id)

        if "updated" in str(event_type):
            self.call_driver(self.build_network(port_net_id), str(event_type))

    def handle_networks(self, context, resource_type, networks, event_type):
        if not networks:
            LOG.error('Networks not present')
            return
        network = dhcp.NetModel(networks[0])
        if 'subnets' not in network:
            network.subnets = []
        network.namespace = network._ns_name
        LOG.debug('DNSMANAGER NETWORK EVENT %s for %s of type %s' % (resource_type, network, event_type))

        if self.network_cache.get(network.id) is not None:
            self.network_cache[network.id] = network
        else:
            self.network_cache[network.id] = network

        self.call_driver(self.build_network(network.id), str(event_type))

    def call_driver(self, network, event_type):
        if network is None:
            LOG.debug("Empty network.")
            return
        if network.subnets is None:
            LOG.debug("No subnets in network. skipping.")
            return
        if network.ports is None:
            LOG.warning("No ports in network. skipping.")
            return
        sid_segment = {}
        sid_subnets = collections.defaultdict(list)
        action = 'enable' if event_type == 'updated' else 'disable'

        DHCP_NS = "qdhcp-%s" % network.id

        network.namespace = DHCP_NS
        network._ns_name = DHCP_NS

        if str(event_type) == 'updated':
            action = "enable"
            # Create namespace, if needed
            ns = self.sh("ip netns | grep %s ; true" % DHCP_NS)
            if not ns:
                self.sh("ip netns add %s" % DHCP_NS)
        else:
            action = "disable"

        LOG.debug("Dns Manager handling network resource event %s :: %s" % (event_type, network))

        if 'segments' in network and network.segments:
            # In case of multi-segments network, let's group network per
            # segments.  We can then create DHPC process per segmentation
            # id. All subnets on a same network that are sharing the same
            # segmentation id will be grouped.
            for segment in network.segments:
                sid_segment[segment.id] = segment
            if 'subnets' in network and network.subnets:
                for subnet in network.subnets:
                    sid_subnets[subnet.get('segment_id')].append(subnet)
        if sid_subnets:
            for seg_id, subnets in sid_subnets.items():
                segment = sid_segment.get(seg_id)
                if segment and segment.segment_index == 0:
                    if action in ['enable', 'disable']:
                        self._call_driver(
                            'disable', network, segment=None, block=True)

                net_seg = copy.deepcopy(network)
                net_seg.subnets = subnets
                self._call_driver(
                    action, net_seg, segment=sid_segment.get(seg_id))
        else:
            self._call_driver(action, network, segment=None)

    def _call_driver(self, action, network, segment=None, **action_kwargs):
        try:
            driver = Dnsmasq(cfg.CONF,
                            network,
                            self._process_monitor,
                            self.dhcp_version,
                            self.plugin_rpc,
                            segment,
                            LOG)
            returnValue = getattr(driver, action)(**action_kwargs)
        except Exception as e:
            LOG.warning("Dns Masq error: %s" % (e))
