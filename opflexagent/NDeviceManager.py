import abc
import collections
import copy
import io
import itertools
import os
import re
import shutil
import signal
import time

import netaddr
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib import constants
from neutron_lib import exceptions
from neutron_lib.utils import file as file_utils
from oslo_concurrency import processutils
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import fileutils
from oslo_utils import netutils
from oslo_utils import uuidutils

from neutron.agent.common import utils as agent_common_utils
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.cmd import runtime_checks as checks
from neutron.common import _constants as common_constants
from neutron.common import utils as common_utils
from neutron.ipam import utils as ipam_utils
from neutron.agent.linux.dhcp import DictModel
from neutron.agent.linux.dhcp import DeviceManager as base_device_manager

LOG = logging.getLogger(__name__)
SIGTERM_TIMEOUT = 5

DNS_PORT = 53
WIN2k3_STATIC_DNS = 249
NS_PREFIX = 'qdhcp-'
DNSMASQ_SERVICE_NAME = 'dnsmasq'
DHCP_RELEASE_TRIES = 3
DHCP_RELEASE_TRIES_SLEEP = 0.3
HOST_DHCPV6_TAG = 'tag:dhcpv6,'

# this variable will be removed when neutron-lib is updated with this value
DHCP_OPT_CLIENT_ID_NUM = 61

class DeviceManager(base_device_manager):

    def __init__(self, conf, plugin):
        super(DeviceManager, self).__init__(conf, plugin)

    def get_dhcp_agent_device_id(self, network_id, host):
        # Split host so as to always use only the hostname and
        # not the domain name. This will guarantee consistency
        # whether a local hostname or an fqdn is passed in.
        #import uuid
        #local_hostname = host.split('.')[0]
        host_uuid = "827da361-9c56-50f7-913f-5a01f7bfed2c" #uuid.uuid5(uuid.NAMESPACE_DNS, str(local_hostname))
        return 'dhcp%s-%s' % (host_uuid, network_id)

    def cleanup_stale_devices(self, network, dhcp_port):
        super(DeviceManager, self).cleanup_stale_devices(network, dhcp_port)

    def plug(self, network, port, interface_name):
        """Plug device settings for the network's DHCP on this host."""
        LOG.warning("NET_PLUGGING %s - %s" % (network.namespace, network))
        self.driver.plug(network.id,
                         port.id,
                         interface_name,
                         port.mac_address,
                         bridge='br-fabric',
                         namespace=network.namespace,
                         mtu=network.get('mtu'))

    def _update_dhcp_port(self, network, port):
        for index in range(len(network.ports)):
            if network.ports[index].id == port.id:
                network.ports[index] = port
                break
        else:
            LOG.warning("APPENDING_PORT")
            #network.ports.append(port)


    def setup(self, network, segment=None):
        """Create and initialize a device for network's DHCP on this host."""
        try:
            port = self.setup_dhcp_port(network, segment)
        except Exception:
            with excutils.save_and_reraise_exception():
                # clear everything out so we don't leave dangling interfaces
                # if setup never succeeds in the future.
                self.cleanup_stale_devices(network, dhcp_port=None)
        self._update_dhcp_port(network, port)
        interface_name = self.get_interface_name(network, port)
        LOG.error("Interface name %s" % (interface_name))

        # Disable acceptance of RAs in the namespace so we don't
        # auto-configure an IPv6 address since we explicitly configure
        # them on the device.  This must be done before any interfaces
        # are plugged since it could receive an RA by the time
        # plug() returns, so we have to create the namespace first.
        # It must also be done in the case there is an existing IPv6
        # address here created via SLAAC, since it will be deleted
        # and added back statically in the call to init_l3() below.
        if network.namespace:
            ip_lib.IPWrapper().ensure_namespace(network.namespace)
            ip_lib.set_ip_nonlocal_bind_for_namespace(network.namespace, 1,
                                                      root_namespace=True)
        if netutils.is_ipv6_enabled():
            self.driver.configure_ipv6_ra(network.namespace, 'default',
                                          constants.ACCEPT_RA_DISABLED)

        if ip_lib.ensure_device_is_ready(interface_name,
                                         namespace=network.namespace):
            LOG.debug('Reusing existing device: %s.', interface_name)
            # force mtu on the port for in case it was changed for the network
            mtu = getattr(network, 'mtu', 0)
            if mtu:
                self.driver.set_mtu(interface_name, mtu,
                                    namespace=network.namespace)
        else:
            try:
                self.plug(network, port, interface_name)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception('Unable to plug DHCP port for '
                                  'network %s. Releasing port.',
                                  network.id)
                    # We should unplug the interface in bridge side.
                    self.unplug(interface_name, network)
                    #self.plugin.release_dhcp_port(network.id, port.device_id)

            self.fill_dhcp_udp_checksums(namespace=network.namespace)
        ip_cidrs = []
        for fixed_ip in port.fixed_ips:
            subnet = fixed_ip.subnet
            net = netaddr.IPNetwork(subnet.cidr)
            ip_cidr = '%s/%s' % (fixed_ip.ip_address, net.prefixlen)
            ip_cidrs.append(ip_cidr)

        if self.driver.use_gateway_ips:
            # For each DHCP-enabled subnet, add that subnet's gateway
            # IP address to the Linux device for the DHCP port.
            for subnet in network.subnets:
                if not subnet.enable_dhcp:
                    continue
                gateway = subnet.gateway_ip
                if gateway:
                    net = netaddr.IPNetwork(subnet.cidr)
                    ip_cidrs.append('%s/%s' % (gateway, net.prefixlen))

        if self.conf.force_metadata or self.conf.enable_isolated_metadata:
            ip_cidrs.append(constants.METADATA_CIDR)
            if netutils.is_ipv6_enabled():
                ip_cidrs.append(common_constants.METADATA_V6_CIDR)

        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=network.namespace)

        self._set_default_route(network, interface_name)
        self.cleanup_stale_devices(network, port)

        return interface_name

    def setup_dhcp_port(self, network, segment=None):
        """Create/update DHCP port for the host if needed and return port."""

        # The ID that the DHCP port will have (or already has).
        #device_id = self.get_device_id(network, segment)
        device_id = None

        # Get the set of DHCP-enabled local subnets on this network.
        dhcp_subnets = {subnet.id: subnet for subnet in network.subnets
                        if subnet.enable_dhcp}

        # There are 3 cases: either the DHCP port already exists (but
        # might need to be updated for a changed set of subnets); or
        # some other code has already prepared a 'reserved' DHCP port,
        # and we just need to adopt that; or we need to create a new
        # DHCP port.  Try each of those in turn until we have a DHCP
        # port.
        dhcp_port = self._setup_existing_dhcp_port(network, device_id, dhcp_subnets)
        if dhcp_port is None:
            raise exceptions.Conflict()

        #self._check_dhcp_port_subnet(dhcp_port, dhcp_subnets, network)

        # Convert subnet_id to subnet dict
        fixed_ips = [dict(subnet_id=fixed_ip.subnet_id,
                          ip_address=fixed_ip.ip_address,
                          subnet=dhcp_subnets[fixed_ip.subnet_id])
                     for fixed_ip in dhcp_port.fixed_ips
                     # we don't care about any ips on subnets irrelevant
                     # to us (e.g. auto ipv6 addresses)
                     if fixed_ip.subnet_id in dhcp_subnets]

        ips = [DictModel(item) if isinstance(item, dict) else item
               for item in fixed_ips]
        dhcp_port.fixed_ips = ips

        return dhcp_port


    def _setup_existing_dhcp_port(self, network, device_id, dhcp_subnets):
        """Set up the existing DHCP port, if there is one."""

        # To avoid pylint thinking that port might be undefined after
        # the following loop...
        port = None

        # Look for an existing DHCP port for this network.
        for port in network.ports:
            #port_device_id = getattr(port, 'device_id', None)
            #LOG.warning("PORT_DEVICE_ID %s vs %s (%s)" % (port_device_id, device_id, port))
            #if port_device_id == device_id:
            if "network:dhcp" in str(port.device_owner) and "ACTIVE" in str(port.status):
                # If using gateway IPs on this port, we can skip the
                # following code, whose purpose is just to review and
                # update the Neutron-allocated IP addresses for the
                # port.
                if self.driver.use_gateway_ips:
                    return port
                # Otherwise break out, as we now have the DHCP port
                # whose subnets and addresses we need to review.
                break
        else:
            return None

        return port
        # Compare what the subnets should be against what is already
        # on the port.
        dhcp_enabled_subnet_ids = set(dhcp_subnets)
        port_subnet_ids = set(ip.subnet_id for ip in port.fixed_ips)

        # If those differ, we need to call update.
        if dhcp_enabled_subnet_ids != port_subnet_ids:
            # Collect the subnets and fixed IPs that the port already
            # has, for subnets that are still in the DHCP-enabled set.
            wanted_fixed_ips = []
            for fixed_ip in port.fixed_ips:
                if fixed_ip.subnet_id in dhcp_enabled_subnet_ids:
                    wanted_fixed_ips.append(
                        {'subnet_id': fixed_ip.subnet_id,
                         'ip_address': fixed_ip.ip_address})

            # Add subnet IDs for new DHCP-enabled subnets.
            wanted_fixed_ips.extend(
                dict(subnet_id=s)
                for s in dhcp_enabled_subnet_ids - port_subnet_ids)

            # Update the port to have the calculated subnets and fixed
            # IPs.  The Neutron server will allocate a fresh IP for
            # each subnet that doesn't already have one.
            port = self.plugin.update_dhcp_port(
                port.id,
                {'port': {'network_id': network.id,
                          'fixed_ips': wanted_fixed_ips}})
            if not port:
                raise exceptions.Conflict()

        return port

    def _setup_new_dhcp_port(self, network, device_id, dhcp_subnets):
        """Create and set up new DHCP port for the specified network."""
        LOG.warning("Attempting to setup new dhcp port. Port will not be created.")
        return None

    def _set_default_route_ip_version(self, network, device_name, ip_version):
        device = ip_lib.IPDevice(device_name, namespace=network.namespace)
        gateway = device.route.get_gateway(ip_version=ip_version)
        if gateway:
            gateway = gateway.get('gateway')

        for subnet in network.subnets:
            skip_subnet = (
                subnet.ip_version != ip_version or
                not subnet.enable_dhcp or
                subnet.gateway_ip is None or
                subnet.subnetpool_id == constants.IPV6_PD_POOL_ID)

            if skip_subnet:
                continue

            if subnet.ip_version == constants.IP_VERSION_6:
                # This is duplicating some of the API checks already done,
                # but some of the functional tests call directly
                prefixlen = netaddr.IPNetwork(subnet.cidr).prefixlen
                if prefixlen == 0 or prefixlen > 126:
                    continue
                modes = [constants.IPV6_SLAAC, constants.DHCPV6_STATELESS]
                addr_mode = getattr(subnet, 'ipv6_address_mode', None)
                ra_mode = getattr(subnet, 'ipv6_ra_mode', None)
                if (prefixlen != 64 and
                        (addr_mode in modes or ra_mode in modes)):
                    continue

            if gateway != subnet.gateway_ip:
                LOG.debug('Setting IPv%(version)s gateway for dhcp netns '
                          'on net %(n)s to %(ip)s',
                          {'n': network.id, 'ip': subnet.gateway_ip,
                           'version': ip_version})

                # Check for and remove the on-link route for the old
                # gateway being replaced, if it is outside the subnet
                is_old_gateway_not_in_subnet = (gateway and
                                                not ipam_utils.check_subnet_ip(
                                                    subnet.cidr, gateway))
                if is_old_gateway_not_in_subnet:
                    onlink = device.route.list_onlink_routes(ip_version)
                    existing_onlink_routes = set(r['cidr'] for r in onlink)
                    if gateway in existing_onlink_routes:
                        device.route.delete_route(gateway, scope='link')

                is_new_gateway_not_in_subnet = (subnet.gateway_ip and
                                                not ipam_utils.check_subnet_ip(
                                                    subnet.cidr,
                                                    subnet.gateway_ip))
                if is_new_gateway_not_in_subnet:
                    device.route.add_route(subnet.gateway_ip, scope='link')
                device.route.add_gateway(subnet.gateway_ip)

            return

        # No subnets on the network have a valid gateway.  Clean it up to avoid
        # confusion from seeing an invalid gateway here.
        if gateway is not None:
            LOG.debug('Removing IPv%(version)s gateway for dhcp netns on '
                      'net %(n)s',
                      {'n': network.id, 'version': ip_version})

            device.route.delete_gateway(gateway)

    def update(self, network, device_name):
        super(DeviceManager, self).update(network, device_name)

    def unplug(self, device_name, network):
        """Unplug device settings for the network's DHCP on this host."""
        self.driver.unplug(device_name, namespace=network.namespace, bridge='br-fabric')

    def destroy(self, network, device_name, segment=None):
        """Destroy the device used for the network's DHCP on this host."""
        if device_name:
            self.unplug(device_name, network)
        else:
            LOG.debug('No interface exists for network %s', network.id)

    def get_interface_name(self, network, port):
        """Return interface(device) name for use by the DHCP process."""
        return self.driver.get_device_name(port)