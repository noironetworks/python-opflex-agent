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

import functools
import hashlib
import json
import multiprocessing
import os
import os.path
import signal
import subprocess  # nosec
import sys
import tempfile
import time
import uuid

import netaddr
import pyinotify
from six.moves import queue as Queue

from neutron.common import config as common_config
from neutron.common import utils
from neutron.conf.agent import common as config
from neutron.plugins.ml2.drivers.openvswitch.agent.common import (  # noqa
    config as ovs_config)
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import encodeutils

from opflexagent._i18n import _
from opflexagent import config as oscfg  # noqa
from opflexagent.utils import utils as opflexagent_utils

LOG = logging.getLogger(__name__)

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
]

EP_FILE_EXTENSION = "ep"
AS_FILE_EXTENSION = "as"
AS_FILE_NAME_FORMAT = "%s." + AS_FILE_EXTENSION
AS_MAPPING_DIR = "/var/lib/opflex-agent-ovs/services"
EOQ = 'STOP'
MD_DIR = "/var/lib/neutron/opflex_agent"
MD_DIR_OWNER = "neutron:neutron"
MD_SUP_FILE_NAME = "metadata.conf"
SVC_IP_DEFAULT = "169.254.1.2"
SVC_IP_BASE = 0xA9FEF003
SVC_IP_SIZE = 1000
SVC_IP_CIDR = 16
SVC_NEXTHOP = "169.254.1.1"
SVC_NS = "of-svc"
SVC_NS_PORT = "of-svc-nsport"
SVC_OVS_PORT = "of-svc-ovsport"
PID_DIR = "/var/lib/neutron/external/pids"
PID_FILE_NAME_FORMAT = PID_DIR + "/%s.pid"
PROXY_FILE_EXTENSION = "proxy"
PROXY_FILE_NAME_FORMAT = "%s." + PROXY_FILE_EXTENSION
SNAT_FILE_EXTENSION = "snat"
SNAT_FILE_NAME_FORMAT = "%s." + SNAT_FILE_EXTENSION
STATE_ANYCAST_SERVICES = "anycast_services"
STATE_INSTANCE_NETWORKS = "instance_networks"
STATE_FILE_EXTENSION = "state"
STATE_FILE_NAME_FORMAT = "%s." + STATE_FILE_EXTENSION
STATE_FILENAME_SVC = STATE_FILE_NAME_FORMAT % STATE_ANYCAST_SERVICES
STATE_FILENAME_NETS = STATE_FILE_NAME_FORMAT % STATE_INSTANCE_NETWORKS


def read_jsonfile(name):
    retval = {}
    try:
        with open(name, "r") as f:
            retval = json.load(f)
    except Exception as e:
        LOG.warn("Exception in reading file: %s", str(e))
    return retval


def write_jsonfile(name, data):
    try:
        with open(name, "w") as f:
            json.dump(data, f)
    except Exception as e:
        LOG.warn("Exception in writing file: %s", str(e))


class AddressPool(object):
    def __init__(self, base, size):
        self.base = base
        self.size = size
        self.ips = {}
        for i in range(size):
            self.ips[self.base + i] = True

    def reserve(self, ip):
        del self.ips[ip]

    def get_addr(self):
        for i in self.ips:
            self.reserve(i)
            return i
        return None


class FileProcessor(object):
    def __init__(self, watchdir, extensions, eventq, processfn):
        self.watchdir = watchdir
        self.extensions = extensions
        self.eventq = eventq
        self.processfn = processfn

    def scanfiles(self, files):
        LOG.debug("FileProcessor: processing files: %s", files)
        relevant_files = []
        for (action, filename) in files:
            if all(not filename.endswith(ext) for ext in self.extensions):
                continue
            relevant_files.append((action, filename))
        LOG.debug("FileProcessor: relevant files %s", relevant_files)
        return self.processfn(relevant_files)

    def scan(self):
        LOG.debug("FileProcessor: initial scan")
        files = []
        for filename in os.listdir(self.watchdir):
            files.append(("update", filename))
        self.scanfiles(files)
        return

    def run(self):
        self.scan()
        try:
            connected = True
            while connected:
                files = []
                event = self.eventq.get()
                while event is not None:
                    # drain all events in queue and batch them
                    LOG.debug("FileProcessor: event: %s", event)
                    if event == EOQ:
                        connected = False
                        event = None
                        break

                    action = "update"
                    if event.maskname == "IN_DELETE" or \
                       event.maskname == "IN_MOVED_FROM":
                        action = "delete"
                    files.append((action, event.pathname))

                    try:
                        event = self.eventq.get_nowait()
                    except Queue.Empty:
                        event = None
                if files:
                    # process the batch
                    self.scanfiles(files)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            LOG.warn("FileProcessor: Exception: %s", str(e))
        return


class EventHandler(pyinotify.ProcessEvent):
    def my_init(self, watcher, extensions):
        self.watcher = watcher
        self.extensions = extensions
        self.events = \
            pyinotify.IN_CLOSE_WRITE | \
            pyinotify.IN_MOVED_FROM | \
            pyinotify.IN_MOVED_TO | \
            pyinotify.IN_DELETE

    def action(self, event):
        if all(not event.pathname.endswith(ext)
                for ext in self.extensions):
            return
        return self.watcher.action(event)
    process_IN_CLOSE_WRITE = action
    process_IN_MOVED_FROM = action
    process_IN_MOVED_TO = action
    process_IN_DELETE = action


class FileWatcher(object):
    def __init__(self, watchdir, extensions, name="Not Specified"):
        self.name = name
        self.watchdir = watchdir
        self.extensions = extensions.split(',')
        self.eventq = multiprocessing.Queue()
        self.auto_restart_fileprocessor = True

        self.start_file_processor()
        LOG.debug("FileWatcher: %s: starting", self.name)

    def action(self, event):
        # event.maskname, event.filename
        LOG.debug("FileWatcher: %(name)s: event: %(event)s",
                  {'name': self.name, 'event': event})
        self.eventq.put(event)

    def process(self, files):
        # Override in child class
        LOG.debug("FileWatcher: %(name)s: process: %(files)s",
                  {'name': self.name, 'files': files})

    def terminate(self, signum, frame):
        self.auto_restart_fileprocessor = False
        self.eventq.put(EOQ)
        if signum is not None:
            sys.exit(0)

    def run(self):
        signal.signal(signal.SIGINT, self.terminate)
        signal.signal(signal.SIGTERM, self.terminate)
        signal.signal(signal.SIGCHLD, self.restart_file_processor)

        wm = pyinotify.WatchManager()
        handler = EventHandler(watcher=self, extensions=self.extensions)
        notifier = pyinotify.Notifier(wm, handler)
        wm.add_watch(self.watchdir, handler.events, rec=False)
        try:
            LOG.debug("FileWatcher: %s: notifier waiting ...", self.name)
            notifier.loop()
        finally:
            LOG.debug("FileWatcher: %s: notifier returned", self.name)
            self.terminate(None, None)

        LOG.debug("FileWatcher: %s: processor returned", self.name)
        return True

    def restart_file_processor(self, signum, frame):
        if (self.processor.is_alive() or
            self.auto_restart_fileprocessor is False):
            return
        self.processor.join()
        self.start_file_processor()
        LOG.debug("FileWatcher: %s: restarting", self.name)

    def start_file_processor(self):
        fp = FileProcessor(
            self.watchdir,
            self.extensions,
            self.eventq,
            functools.partial(self.process))
        fprun = functools.partial(fp.run)
        self.processor = multiprocessing.Process(target=fprun)
        self.processor.start()


class TmpWatcher(FileWatcher):
    """Class for integration testing"""
    def __init__(self):
        filedir = tempfile.gettempdir()
        extensions = EP_FILE_EXTENSION
        super(TmpWatcher, self).__init__(
            filedir, extensions, name="ep-watcher")

    def process(self, files):
        LOG.debug("TmpWatcher files: %s", files)


class EpWatcher(FileWatcher):
    """EpWatcher watches EPs and generates two state files:
    anycast_services.state:
        maps domain -> AS services for that domains
    instance_networks.state:
        maps IP -> neutron-network for each EP in that domain

    anycast_services = {
        'domain-uuid-1': {
            'domain-name': domain_name,
            'domain-policy-space': domain_tenant,
            'next-hop-ip': anycast_svc_ip,
            'uuid': domain_uuid
        },
        ...
        'domain-uuid-n': {
            <anycast svc specification above>
        }
    }

    instance_networks = {
        'domain-uuid-1': {
            'ip-addr-1': 'neutron-network',
            ...
            'ip-addr-n': 'neutron-network'
        },
        'domain-uuid-n': {
            'ip-addr-1': 'neutron-network',
            ...
            'ip-addr-n': 'neutron-network'
        }
    }

    """
    def __init__(self):
        self.svcfile = "%s/%s" % (MD_DIR, STATE_FILENAME_SVC)
        self.netsfile = "%s/%s" % (MD_DIR, STATE_FILENAME_NETS)

        epfiledir = cfg.CONF.OPFLEX.epg_mapping_dir
        epextensions = EP_FILE_EXTENSION
        super(EpWatcher, self).__init__(
            epfiledir, epextensions, name="ep-watcher")

    def gen_domain_uuid(self, tenant, name):
        fqname = '%s|%s' % (tenant, name)
        fqhash = hashlib.md5(fqname.encode('utf-8')).hexdigest()  # nosec
        fquuid = str(uuid.UUID(fqhash))
        return fquuid

    def process(self, files):
        LOG.debug("EP files: %s", files)

        curr_svc = read_jsonfile(self.svcfile)
        ip_pool = AddressPool(SVC_IP_BASE, SVC_IP_SIZE)
        for domain_uuid in curr_svc:
            thisip = netaddr.IPAddress(curr_svc[domain_uuid]['next-hop-ip'])
            ip_pool.reserve(int(thisip))

        new_svc = {}
        new_nets = {}
        updated = False

        epfiledir = cfg.CONF.OPFLEX.epg_mapping_dir
        for filename in os.listdir(epfiledir):
            if not filename.endswith(EP_FILE_EXTENSION):
                continue

            filename = "%s/%s" % (epfiledir, filename)
            ep = read_jsonfile(filename)
            if ep:
                metadata_optimization = ep.get(
                    'neutron-metadata-optimization',
                    False)
                if metadata_optimization is False:
                    # No service file when metadata optimization is False,
                    # as for VMs on vlan type nets. But we can have another
                    # VM on an opflex type net on the same compute which can
                    # have metadata optimization, so we continue and a service
                    # file can be generated.
                    continue

                domain_name = ep.get('domain-name')
                domain_tenant = ep.get('domain-policy-space')
                if domain_name is None or domain_tenant is None:
                    continue

                domain_uuid = self.gen_domain_uuid(domain_tenant, domain_name)
                if domain_uuid and domain_uuid not in new_svc:
                    if domain_uuid not in curr_svc:
                        updated = True
                        as_uuid = domain_uuid
                        as_addr = netaddr.IPAddress(ip_pool.get_addr())
                        as_addr = str(as_addr)
                        new_svc[domain_uuid] = {
                            'domain-name': domain_name,
                            'domain-policy-space': domain_tenant,
                            'next-hop-ip': as_addr,
                            'uuid': as_uuid,
                        }
                    else:
                        new_svc[domain_uuid] = curr_svc[domain_uuid]
                        del curr_svc[domain_uuid]

                nnetwork = ep.get('neutron-network')
                if nnetwork is None:
                    continue

                ips = ep.get('anycast-return-ip')
                if ips is None:
                    ips = []

                if domain_uuid not in new_nets:
                    new_nets[domain_uuid] = {}
                for ip in ips:
                    new_nets[domain_uuid][ip] = nnetwork

        if curr_svc:
            updated = True

        if updated:
            write_jsonfile(self.svcfile, new_svc)
        write_jsonfile(self.netsfile, new_nets)


class StateWatcher(FileWatcher):
    def __init__(self):
        root_helper = cfg.CONF.AGENT.root_helper
        self.mgr = AsMetadataManager(LOG, root_helper)
        self.svcfile = "%s/%s" % (MD_DIR, STATE_FILENAME_SVC)
        self.svc_ovsport_mac = self.mgr.get_asport_mac()[:17]
        self.disable_proxy = cfg.CONF.OPFLEX.disable_metadata_proxy

        stfiledir = MD_DIR
        stextensions = STATE_FILE_EXTENSION
        super(StateWatcher, self).__init__(
            stfiledir, stextensions, name="state-watcher")

    def terminate(self, signum, frame):
        self.mgr.ensure_terminated()
        super(StateWatcher, self).terminate(signum, frame)

    def process(self, files):
        LOG.debug("State Event: %s", files)

        curr_alloc = read_jsonfile(self.svcfile)

        updated = False
        asfiledir = cfg.CONF.OPFLEX.as_mapping_dir
        for filename in os.listdir(asfiledir):
            if not filename.endswith(AS_FILE_EXTENSION):
                continue

            filename = "%s/%s" % (asfiledir, filename)
            asvc = read_jsonfile(filename)
            if asvc:
                domain_uuid = asvc["uuid"]
                if domain_uuid not in curr_alloc:
                    updated = True
                    self.as_del(filename, asvc)
                else:
                    if not self.as_equal(asvc, curr_alloc[domain_uuid]):
                        updated = True
                        self.as_write(curr_alloc[domain_uuid], filename, asvc)
                    del curr_alloc[domain_uuid]

        for domain_uuid in curr_alloc:
            updated = True
            self.as_create(curr_alloc[domain_uuid])

        if updated:
            self.mgr.update_supervisor()

    def as_write(self, alloc, filename, asvc):
        self.as_del(filename, asvc)
        self.as_create(alloc)

    def as_equal(self, asvc, alloc):
        for idx in ["uuid", "domain-name", "domain-policy-space"]:
            if asvc[idx] != alloc[idx]:
                return False
        if asvc["service-mapping"][0]["next-hop-ip"] != alloc["next-hop-ip"]:
            return False
        return True

    def as_del(self, filename, asvc):
        try:
            self.mgr.del_ip(asvc["service-mapping"][0]["next-hop-ip"])
        except Exception as e:
            LOG.warn("EPwatcher: Exception in deleting IP: %s",
                     str(e))

        proxyfilename = PROXY_FILE_NAME_FORMAT % asvc["uuid"]
        proxyfilename = "%s/%s" % (MD_DIR, proxyfilename)
        try:
            os.remove(filename)
            os.remove(proxyfilename)
        except Exception as e:
            LOG.warn("EPwatcher: Exception in deleting file: %s", str(e))

    def as_create(self, alloc):
        asvc = {
            "uuid": alloc["uuid"],
            "interface-name": SVC_OVS_PORT,
            "service-mac": self.svc_ovsport_mac,
            "domain-policy-space": alloc["domain-policy-space"],
            "domain-name": alloc["domain-name"],
            "service-mapping": [
                {
                    "service-ip": "169.254.169.254",
                    "gateway-ip": "169.254.1.1",
                    "next-hop-ip": alloc["next-hop-ip"],
                },
            ],
        }

        try:
            self.mgr.add_ip(alloc["next-hop-ip"])
        except Exception as e:
            LOG.warn("EPwatcher: Exception in adding IP: %s",
                     str(e))

        asfilename = AS_FILE_NAME_FORMAT % asvc["uuid"]
        asfilename = "%s/%s" % (AS_MAPPING_DIR, asfilename)
        write_jsonfile(asfilename, asvc)

        if not self.disable_proxy:
            proxyfilename = PROXY_FILE_NAME_FORMAT % asvc["uuid"]
            proxyfilename = "%s/%s" % (MD_DIR, proxyfilename)
            proxystr = self.proxyconfig(alloc)
            try:
                with open(proxyfilename, "w") as f:
                    f.write(proxystr)
                pidfile = PID_FILE_NAME_FORMAT % asvc["uuid"]
                self.mgr.sh("rm -f %s" % pidfile)
            except Exception as e:
                LOG.warn("EPwatcher: Exception in writing proxy file: %s",
                         str(e))

    def proxyconfig(self, alloc):
        duuid = alloc["uuid"]
        ipaddr = alloc["next-hop-ip"]
        proxystr = "\n".join([
            "[program:opflex-ns-proxy-%s]" % duuid,
            "command=ip netns exec of-svc "
            "/usr/bin/opflex-ns-proxy "
            "--metadata_proxy_socket=/var/lib/neutron/metadata_proxy "
            "--state_path=/var/lib/neutron "
            "--pid_file=/var/lib/neutron/external/pids/%s.pid "
            "--domain_id=%s --metadata_host %s --metadata_port=80 "
            "--log-dir=/var/log/neutron --log-file=opflex-ns-proxy-%s.log" % (
                duuid, duuid, ipaddr, duuid[:8]),
            "exitcodes=0,2",
            "stopasgroup=true",
            "startsecs=10",
            "startretries=3",
            "stopwaitsecs=10",
            "stdout_logfile=NONE",
            "stderr_logfile=NONE",
        ])
        return proxystr


class SnatConnTrackHandler(object):
    def __init__(self):
        root_helper = cfg.CONF.AGENT.root_helper
        self.mgr = AsMetadataManager(LOG, root_helper)
        self.syslog_facility = cfg.CONF.OPFLEX.conn_track_syslog_facility
        self.syslog_severity = cfg.CONF.OPFLEX.conn_track_syslog_severity

    def conn_track_create(self, netns):
        snatfilename = SNAT_FILE_NAME_FORMAT % netns
        snatfilename = "%s/%s" % (MD_DIR, snatfilename)
        conn_track_str = self.conn_track_config(netns)
        try:
            with open(snatfilename, "w") as f:
                f.write(conn_track_str)
            pidfile = PID_FILE_NAME_FORMAT % netns
            self.mgr.sh("rm -f %s" % pidfile)
            self.mgr.update_supervisor()
        except Exception as e:
            LOG.warn("ConnTrack: Exception in writing snat file: %s",
                     str(e))

    def conn_track_del(self, netns):
        snatfilename = SNAT_FILE_NAME_FORMAT % netns
        snatfilename = "%s/%s" % (MD_DIR, snatfilename)
        try:
            os.remove(snatfilename)
            self.mgr.update_supervisor()
        except Exception as e:
            LOG.warn("ConnTrack: Exception in deleting file: %s", str(e))

    def conn_track_config(self, netns):
        snatstr = "\n".join([
            "[program:opflex-conn-track-%s]" % netns,
            "command=/usr/bin/opflex-conn-track %s %s %s" % (
                netns, self.syslog_facility, self.syslog_severity),
            "exitcodes=0,2",
            "stopasgroup=true",
            "startsecs=10",
            "startretries=3",
            "stopwaitsecs=10",
            "stdout_logfile=NONE",
            "stderr_logfile=NONE",
        ])
        return snatstr


class AsMetadataManager(object):
    def __init__(self, logger, root_helper):
        global LOG
        LOG = logger
        self.root_helper = root_helper
        self.name = "AsMetadataManager"
        self.md_filename = "%s/%s" % (MD_DIR, MD_SUP_FILE_NAME)
        self.bridge_manager = opflexagent_utils.get_bridge_manager(
                              cfg.CONF.OPFLEX)
        self.initialized = False
        self.disable_proxy = cfg.CONF.OPFLEX.disable_metadata_proxy

    def init_all(self):
        self.init_host()
        self.init_supervisor()
        self.start_supervisor()
        return

    def ensure_initialized(self):
        if not self.initialized:
            try:
                self.clean_files()
                self.init_all()
                self.initialized = True
            except Exception as e:
                LOG.error("%(name)s: in initializing anycast metadata "
                          "service: %(exc)s",
                          {'name': self.name, 'exc': str(e)})

    def ensure_terminated(self):
        if self.initialized:
            try:
                self.initialized = False
                self.clean_files()
                self.stop_supervisor()
            except Exception as e:
                LOG.error("%(name)s: in shuttingdown anycast metadata "
                          "service: %(exc)s",
                          {'name': self.name, 'exc': str(e)})

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
            LOG.error("In running command: %(cmd)s: %(exc)s",
                      {'cmd': cmd, 'exc': str(e)})
        LOG.debug("%(name)s: Command output: %(ret)s",
                  {'name': self.name, 'ret': ret})
        return ret

    def write_file(self, name, data):
        LOG.debug("%(name)s: Writing file: name=%(file)s, data=%(data)s",
                  {'name': self.name, 'file': name, 'data': data})
        with open(name, "w") as f:
            f.write(data)

    def clean_files(self):
        def rm_files(dirname, extension):
            ignorelist = ['anycast_services.state']
            try:
                for filename in os.listdir(dirname):
                    if (filename.endswith('.' + extension) and
                        filename not in ignorelist):
                        os.remove("%s/%s" % (dirname, filename))
            except Exception as e:
                LOG.info("Exception occurred while removing files."
                         " error: %s", str(e))
        rm_files(AS_MAPPING_DIR, AS_FILE_EXTENSION)
        rm_files(MD_DIR, STATE_FILE_EXTENSION)
        rm_files(MD_DIR, PROXY_FILE_EXTENSION)
        rm_files(MD_DIR, '.conf')

    def start_supervisor(self):
        self.stop_supervisor()
        self.sh("supervisord -c %s" % self.md_filename)

    def update_supervisor(self):
        self.sh("supervisorctl -c %s reread" % self.md_filename)
        self.sh("supervisorctl -c %s update" % self.md_filename)

    def reload_supervisor(self):
        self.sh("supervisorctl -c %s reload" % self.md_filename)

    def stop_supervisor(self):
        self.sh("supervisorctl -c %s shutdown" % self.md_filename)
        time.sleep(30)

    def add_default_route(self, nexthop):
        self.sh("ip netns exec %s ip route add default via %s" %
                (SVC_NS, nexthop))

    def has_ip(self, ipaddr):
        outp = self.sh("ip netns exec %s ip addr show dev %s" %
                (SVC_NS, SVC_NS_PORT))
        return 'net %s/' % (ipaddr, ) in outp

    def add_ip(self, ipaddr):
        if self.has_ip(ipaddr):
            return
        self.sh("ip netns exec %s ip addr add %s/%s dev %s" %
                (SVC_NS, ipaddr, SVC_IP_CIDR, SVC_NS_PORT))

    def del_ip(self, ipaddr):
        if not self.has_ip(ipaddr):
            return
        self.sh("ip netns exec %s ip addr del %s/%s dev %s" %
                (SVC_NS, ipaddr, SVC_IP_CIDR, SVC_NS_PORT))

    def get_asport_mac(self):
        return self.sh(
            "ip netns exec %s ip link show %s | "
            "gawk -e '/link\/ether/ {print $2}'" %
            (SVC_NS, SVC_NS_PORT))

    def init_host(self):
        # Create required directories
        self.sh("mkdir -p %s" % PID_DIR)
        self.sh("rm -f %s/*.pid" % PID_DIR)
        self.sh("chown %s %s" % (MD_DIR_OWNER, PID_DIR))
        self.sh("chown %s %s/.." % (MD_DIR_OWNER, PID_DIR))
        self.sh("mkdir -p %s" % MD_DIR)
        self.sh("chown %s %s" % (MD_DIR_OWNER, MD_DIR))

        # Create namespace, if needed
        ns = self.sh("ip netns | grep %s ; true" % SVC_NS)
        if not ns:
            self.sh("ip netns add %s" % SVC_NS)

        # Create ports, if needed
        port = self.sh("ip link show %s 2>&1 | grep qdisc ; true" %
                       SVC_OVS_PORT)
        if not port:
            self.sh("ip link add %s type veth peer name %s" %
                    (SVC_NS_PORT, SVC_OVS_PORT))
            self.sh("ip link set dev %s up" % SVC_OVS_PORT)
            self.sh("ip link set %s netns %s" % (SVC_NS_PORT, SVC_NS))
            self.sh("ip netns exec %s ip link set dev %s up" %
                    (SVC_NS, SVC_NS_PORT))
            self.add_ip(SVC_IP_DEFAULT)
            self.add_default_route(SVC_NEXTHOP)
            self.sh("ethtool --offload %s tx off" % SVC_OVS_PORT)
            self.sh("ip netns exec %s ethtool --offload %s tx off" %
                    (SVC_NS, SVC_NS_PORT))
        self.bridge_manager.plug_metadata_port(self.sh, SVC_OVS_PORT)

    def init_supervisor(self):
        def conf(*fnames):
            config_str = ''
            for fname in fnames:
                if os.path.exists(fname):
                    if os.path.isfile(fname):
                        config_str += '--config-file %s ' % fname
                    elif os.path.isdir(fname):
                        config_str += '--config-dir %s ' % fname
            return config_str

        config_str = "\n".join([
            "[rpcinterface:supervisor]",
            "supervisor.rpcinterface_factory = "
            "supervisor.rpcinterface:make_main_rpcinterface",
            "",
            "[unix_http_server]",
            "file = /var/lib/neutron/opflex_agent/md-svc-supervisor.sock",
            "",
            "[supervisorctl]",
            "serverurl = "
            "unix:///var/lib/neutron/opflex_agent/md-svc-supervisor.sock",
            "prompt = md-svc",
            "",
            "[supervisord]",
            "identifier = md-svc-supervisor",
            "pidfile = /var/lib/neutron/opflex_agent/md-svc-supervisor.pid",
            "logfile = /var/log/neutron/metadata-supervisor.log",
            "logfile_maxbytes = 10MB",
            "logfile_backups = 3",
            "loglevel = debug",
            "childlogdir = /var/log/neutron",
            "umask = 022",
            "minfds = 1024",
            "minprocs = 200",
            "nodaemon = false",
            "nocleanup = false",
            "strip_ansi = false",
            "",
        ])
        if not self.disable_proxy:
            config_str += "\n".join([
                "[program:metadata-agent]",
                "command=/usr/bin/neutron-metadata-agent " +
                conf('/usr/share/neutron/neutron-dist.conf',
                     '/etc/neutron/neutron.conf',
                     '/etc/neutron/metadata_agent.ini',
                     '/etc/neutron/conf.d/neutron-metadata-agent') +
                "--log-file /var/log/neutron/metadata-agent.log",
                "exitcodes=0,2",
                "stopasgroup=true",
                "startsecs=10",
                "startretries=3",
                "stopwaitsecs=10",
                "stdout_logfile=NONE",
                "stderr_logfile=NONE",
                "",
            ])
        config_str += "\n".join([
            "[program:opflex-ep-watcher]",
            "command=/usr/bin/opflex-ep-watcher " +
            conf('/usr/share/neutron/neutron-dist.conf',
                 '/etc/neutron/neutron.conf',
                 '/etc/neutron/plugins/ml2/ml2_conf_cisco.ini') +
            "--log-file /var/log/neutron/opflex-ep-watcher.log",
            "exitcodes=0,2",
            "stopasgroup=true",
            "startsecs=10",
            "startretries=3",
            "stopwaitsecs=10",
            "stdout_logfile=NONE",
            "stderr_logfile=NONE",
            "",
            "[program:opflex-state-watcher]",
            "command=/usr/bin/opflex-state-watcher " +
            conf('/usr/share/neutron/neutron-dist.conf',
                 '/etc/neutron/neutron.conf',
                 '/etc/neutron/plugins/ml2/ml2_conf_cisco.ini') +
            "--log-file /var/log/neutron/opflex-state-watcher.log",
            "exitcodes=0,2",
            "stopasgroup=true",
            "startsecs=10",
            "startretries=3",
            "stopwaitsecs=10",
            "stdout_logfile=NONE",
            "stderr_logfile=NONE",
            "",
            "[include]",
            "files = %s/*.proxy %s/*.snat" % (MD_DIR, MD_DIR),
        ])
        config_file = "%s/%s" % (MD_DIR, MD_SUP_FILE_NAME)
        self.write_file(config_file, config_str)


def init_env():
    common_config.register_common_config_options()
    config.register_root_helper(cfg.CONF)
    # importing ovs_config got OVS registered
    cfg.CONF.register_opts(gbp_opts, "OPFLEX")
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    config.setup_privsep()
    utils.log_opt_values(LOG)


def tmp_watcher_main():
    init_env()
    TmpWatcher().run()


def ep_watcher_main():
    init_env()
    EpWatcher().run()


def state_watcher_main():
    init_env()
    StateWatcher().run()


def as_metadata_main():
    init_env()
    root_helper = cfg.CONF.AGENT.root_helper
    asm = AsMetadataManager(LOG, root_helper)
    asm.ensure_initialized()


if __name__ == "__main__":
    tmp_watcher_main()
