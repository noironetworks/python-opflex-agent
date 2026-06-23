from neutron.agent.linux.dhcp import Dnsmasq as baseDnsmasq
from neutron.agent.linux.dhcp import port_requires_dhcp_configuration
from neutron.agent.linux.dhcp import DictModel
from neutron.common import utils as common_utils
from oslo_utils import excutils

import os
import io
import netaddr
import json
import shutil
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
from opflexagent.NDeviceManager import DeviceManager

HOST_DHCPV6_TAG = 'tag:dhcpv6,'
AS_MAPPING_DIR = "/var/lib/opflex/files/services"

class Dnsmasq(baseDnsmasq):
    def __init__(self, conf, network, process_monitor, version=None,
                 plugin=None, segment=None, log=None):
        self.LOG = log
        self.service_files = set()
        super(baseDnsmasq, self).__init__(conf, network, process_monitor,
                                               version, plugin)
        self.device_manager = DeviceManager(self.conf, plugin)

    def enable(self):
        """Enables DHCP for this network by spawning a local process."""
        self.LOG.warning("Enabling DHCP for a network")
        try:
            common_utils.wait_until_true(self._enable, timeout=300)
        except common_utils.WaitTimeout:
            self.LOG.error("Failed to start DHCP process for network %s",
                      self.network.id)

    def _output_hosts_file(self):
        return

    def _get_dns_assignment(self, ip_address, dns_assignment):
        return super(Dnsmasq, self)._get_dns_assignment(str(ip_address), dns_assignment)
    
    def _build_cmdline_callback(self, pid_file):
        # We ignore local resolv.conf if dns servers are specified
        # or if local resolution is explicitly disabled.
        _no_resolv = (
            '--no-resolv' if self.conf.dnsmasq_dns_servers or
            not self.conf.dnsmasq_local_resolv else '')
        cmd = [
            'dnsmasq',
            '--no-hosts',
            _no_resolv,
            '--pid-file=%s' % pid_file,
            '--dhcp-hostsfile=%s' % self.get_conf_file_name('host'),
            '--addn-hosts=%s' % self.get_conf_file_name('addn_hosts'),
            '--dhcp-optsfile=%s' % self.get_conf_file_name('opts'),
            '--dhcp-leasefile=%s' % self.get_conf_file_name('leases'),
            '--dhcp-match=set:ipxe,175',
            '--dhcp-userclass=set:ipxe6,iPXE',
            #'--local-service',
            '--bind-dynamic',
        ]
        if not self.device_manager.driver.bridged:
            cmd += [
                '--bridge-interface=%s,tap*' % self.interface_name,
            ]

        possible_leases = 0
        for subnet in self._get_all_subnets(self.network):
            mode = None
            # if a subnet is specified to have dhcp disabled
            if not subnet.enable_dhcp:
                continue
            if subnet.ip_version == 4:
                mode = 'static'
            else:
                # Note(scollins) If the IPv6 attributes are not set, set it as
                # static to preserve previous behavior
                addr_mode = getattr(subnet, 'ipv6_address_mode', None)
                ra_mode = getattr(subnet, 'ipv6_ra_mode', None)
                if (addr_mode in [constants.DHCPV6_STATEFUL,
                                  constants.DHCPV6_STATELESS] or
                        not addr_mode and not ra_mode):
                    mode = 'static'

            cidr = netaddr.IPNetwork(subnet.cidr)

            if self.conf.dhcp_lease_duration == -1:
                lease = 'infinite'
            else:
                lease = '%ss' % self.conf.dhcp_lease_duration

            # mode is optional and is not set - skip it
            if mode:
                if subnet.ip_version == 4:
                    cmd.append('--dhcp-range=%s%s,%s,%s,%s,%s' %
                               ('set:', self._SUBNET_TAG_PREFIX % subnet.id,
                                cidr.network, mode, cidr.netmask, lease))
                else:
                    if cidr.prefixlen < 64:
                        self.LOG.debug('Ignoring subnet %(subnet)s, CIDR has '
                                  'prefix length < 64: %(cidr)s',
                                  {'subnet': subnet.id, 'cidr': cidr})
                        continue
                    cmd.append('--dhcp-range=%s%s,%s,%s,%d,%s' %
                               ('set:', self._SUBNET_TAG_PREFIX % subnet.id,
                                cidr.network, mode,
                                cidr.prefixlen, lease))
                possible_leases += cidr.size

        mtu = getattr(self.network, 'mtu', 0)
        # Do not advertise unknown mtu
        if mtu > 0:
            cmd.append('--dhcp-option-force=option:mtu,%d' % mtu)

        # Cap the limit because creating lots of subnets can inflate
        # this possible lease cap.
        cmd.append('--dhcp-lease-max=%d' %
                   min(possible_leases, self.conf.dnsmasq_lease_max))

        if self.conf.dhcp_renewal_time > 0:
            cmd.append('--dhcp-option-force=option:T1,%ds' %
                       self.conf.dhcp_renewal_time)

        if self.conf.dhcp_rebinding_time > 0:
            cmd.append('--dhcp-option-force=option:T2,%ds' %
                       self.conf.dhcp_rebinding_time)

        cmd.append('--conf-file=%s' %
                   (self.conf.dnsmasq_config_file.strip() or '/dev/null'))
        for server in self.conf.dnsmasq_dns_servers:
            cmd.append('--server=%s' % server)

        if self.conf.dns_domain:
            cmd.append('--domain=%s' % self.conf.dns_domain)

        if self.conf.dhcp_broadcast_reply:
            cmd.append('--dhcp-broadcast')

        if self.conf.dnsmasq_base_log_dir:
            log_dir = os.path.join(
                self.conf.dnsmasq_base_log_dir,
                self.network.id)
            try:
                if not os.path.exists(log_dir):
                    os.makedirs(log_dir)
            except OSError:
                self.LOG.error('Error while create dnsmasq log dir: %s', log_dir)
            else:
                log_filename = os.path.join(log_dir, 'dhcp_dns_log')
                cmd.append('--log-queries')
                cmd.append('--log-dhcp')
                cmd.append('--log-facility=%s' % log_filename)

        return cmd
    
    def _iter_hosts(self, merge_addr6_list=False):
        """Iterate over hosts.

        For each host on the network we yield a tuple containing:
        (
            port,  # a DictModel instance representing the port.
            alloc,  # a DictModel instance of the allocated ip and subnet.
                    # if alloc is None, it means there is no need to allocate
                    # an IPv6 address because of stateless DHCPv6 network.
            host_name,  # Host name.
            name,  # Canonical hostname in the format 'hostname[.domain]'.
            no_dhcp,  # A flag indicating that the address doesn't need a DHCP
                      # IP address.
            no_opts,  # A flag indication that options shouldn't be written
            tag,    # A dhcp-host tag to add to the configuration if supported
        )
        """
        v6_nets = dict((subnet.id, subnet) for subnet in
                       self._get_all_subnets(self.network)
                       if subnet.ip_version == 6)

        for port in self.network.ports:
            if not port_requires_dhcp_configuration(port):
                continue

            fixed_ips = self._sort_fixed_ips_for_dnsmasq(port.fixed_ips,
                                                         v6_nets)
            # TODO(hjensas): Drop this conditional and option once distros
            #  generally have dnsmasq supporting addr6 list and range.
            if self.conf.dnsmasq_enable_addr6_list and merge_addr6_list:
                fixed_ips = self._merge_alloc_addr6_list(fixed_ips, v6_nets)
            # Confirm whether Neutron server supports dns_name attribute in the
            # ports API
            dns_assignment = getattr(port, 'dns_assignment', None)
            for alloc in fixed_ips:
                no_dhcp = False
                no_opts = False
                tag = ''
                if alloc.subnet_id in v6_nets:
                    addr_mode = v6_nets[alloc.subnet_id].ipv6_address_mode
                    no_dhcp = addr_mode in (constants.IPV6_SLAAC,
                                            constants.DHCPV6_STATELESS)
                    if self._is_dnsmasq_host_tag_supported():
                        tag = HOST_DHCPV6_TAG
                    # we don't setup anything for SLAAC. It doesn't make sense
                    # to provide options for a client that won't use DHCP
                    no_opts = addr_mode == constants.IPV6_SLAAC

                hostname, fqdn = self._get_dns_assignment(alloc.ip_address,
                                                          dns_assignment)

                yield (port, alloc, hostname, fqdn, no_dhcp, no_opts, tag)

    def _output_config_files(self):
        self._output_hosts_file()
        self._output_addn_hosts_file()
        self._output_opts_file()
        self._output_service_file()

    def _output_hosts_file(self):
        """Writes a dnsmasq compatible dhcp hosts file.

        The generated file is sent to the --dhcp-hostsfile option of dnsmasq,
        and lists the hosts on the network which should receive a dhcp lease.
        Each line in this file is in the form::

            'mac_address,FQDN,ip_address'

        IMPORTANT NOTE: a dnsmasq instance does not resolve hosts defined in
        this file if it did not give a lease to a host listed in it (e.g.:
        multiple dnsmasq instances on the same network if this network is on
        multiple network nodes). This file is only defining hosts which
        should receive a dhcp lease, the hosts resolution in itself is
        defined by the `_output_addn_hosts_file` method.
        """
        buf = io.StringIO()
        filename = self.get_conf_file_name('host')

        self.LOG.debug('Building host file: %s', filename)
        dhcp_enabled_subnet_ids = [s.id for s in
                                   self._get_all_subnets(self.network)
                                   if s.enable_dhcp]
        # NOTE(ihrachyshka): the loop should not log anything inside it, to
        # avoid potential performance drop when lots of hosts are dumped
        for host_tuple in self._iter_hosts(merge_addr6_list=True):
            port, alloc, hostname, name, no_dhcp, no_opts, tag = host_tuple
            if no_dhcp:
                if not no_opts and self._get_port_extra_dhcp_opts(port):
                    buf.write('%s,%s%s%s\n' % (
                        port.mac_address, tag,
                        'set:', self._PORT_TAG_PREFIX % port.id))
                continue

            # don't write ip address which belongs to a dhcp disabled subnet.
            if alloc.subnet_id not in dhcp_enabled_subnet_ids:
                continue

            ip_address = self._format_address_for_dnsmasq(alloc.ip_address)

            if self._get_port_extra_dhcp_opts(port):
                client_id = self._get_client_id(port)
                if client_id and len(port.extra_dhcp_opts) > 1:
                    buf.write('%s,%s%s%s,%s,%s,%s%s\n' %
                              (port.mac_address, tag, self._ID, client_id,
                               name, ip_address, 'set:',
                               self._PORT_TAG_PREFIX % port.id))
                elif client_id and len(port.extra_dhcp_opts) == 1:
                    buf.write('%s,%s%s%s,%s,%s\n' %
                              (port.mac_address, tag, self._ID, client_id,
                               name, ip_address))
                else:
                    buf.write('%s,%s%s,%s,%s%s\n' %
                              (port.mac_address, tag, name, ip_address,
                               'set:', self._PORT_TAG_PREFIX % port.id))
            else:
                buf.write('%s,%s%s,%s\n' %
                          (port.mac_address, tag, name, ip_address))

        file_utils.replace_file(filename, buf.getvalue())
        self.LOG.debug('Done building host file %s\n%s' % (filename, buf.getvalue()))
        return filename
    
    def _output_service_file(self):
        self.LOG.debug("Outputting service file.")
        pGatewayIp = ""

        for port in self.network.ports:
            if 'network:router_interface' not in port.device_owner:
                continue
            pGatewayIp = port.fixed_ips[0].ip_address
            break

        for port in self.network.ports:
            if 'network:dhcp' not in port.device_owner:
                continue

            uuid = port.id
            interface_namespace = self.network.namespace
            interface_name = "tap%s" % port.id[0:11]
            proj = "prj_%s" % port.project_id
            service_mac = ""
            pIp = port.fixed_ips[0].ip_address
            asFileName = "%s.as" % uuid

            ip_wrapper_root = ip_lib.IPWrapper(interface_namespace)
            if_dev = ip_wrapper_root.device(interface_name)

            if if_dev.exists() is False:
                return
             
            service_mac = str(if_dev.link.address)

            asvc = {
                "uuid": uuid,
                "interface-name": interface_name,
                "service-mac": service_mac,
                "domain-policy-space": proj,
                "domain-name": "DefaultVRF",
                "service-mapping": [
                    {
                        "service-ip": str(pIp),
                        "gateway-ip": pGatewayIp,
                        "next-hop-ip": str(pIp),
                    },
                ],
            }

            fileLoc = "%s/%s" % (AS_MAPPING_DIR, asFileName)

            self.LOG.warning("WRITE_SERVICE_FILE:\n%s\n%s" % (asvc, fileLoc))
            self.write_jsonfile(fileLoc, asvc)
            self.service_files.add(fileLoc)

    def write_jsonfile(self, name, data):
        try:
            with open(name, "w") as f:
                json.dump(data, f)
        except Exception as e:
            self.LOG.warning("Exception in writing file: %s", str(e))

    def _remove_config_files(self):
        shutil.rmtree(self.network_conf_dir, ignore_errors=True)
        try:
            for serviceFileLocation in self.service_files:
                if AS_MAPPING_DIR not in serviceFileLocation:
                    continue
                os.remove(serviceFileLocation)
        except Exception as e:
            self.LOG.warn("Dnsmasq: Exception in deleting file: %s", str(e))