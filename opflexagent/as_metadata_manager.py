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
import multiprocessing
import netaddr
import os
import pyinotify
import Queue
import signal
import subprocess
import sys

from neutron.common import config as common_config
from neutron.common import utils
from neutron.openstack.common import log as logging
from neutron.plugins.openvswitch.common import config as ovs_config  # noqa
from oslo.config import cfg
from oslo.serialization import jsonutils

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
MD_MAP_FILE_NAME = "metadata.map"
MD_SUP_FILE_NAME = "metadata.conf"
SVC_IP_DEFAULT = "169.254.1.2"
SVC_IP_BASE = 0xA9FEF003
SVC_IP_MAX = 0xA9FEFFFE
SVC_IP_CIDR = 16
SVC_NEXTHOP = "169.254.1.1"
SVC_NS = "of-svc"
SVC_NS_PORT = "of-svc-nsport"
SVC_OVS_PORT = "of-svc-ovsport"
PID_DIR = "/var/lib/neutron/external/pids"
PROXY_FILE_EXTENSION = "proxy"
PROXY_FILE_NAME_FORMAT = "%s." + PROXY_FILE_EXTENSION
STATE_FILE_EXTENSION = "state"
STATE_FILE_NAME_FORMAT = "%s." + STATE_FILE_EXTENSION
STATE_IPADDR_ALLLOC = "ipaddr_alloc"


class FileProcessor(object):
    def __init__(self, watchdir, extensions, eventq, processfn):
        self.watchdir = watchdir
        self.extensions = extensions
        self.eventq = eventq
        self.processfn = processfn

    def scanfiles(self, files):
        LOG.debug("FileProcessor: processing files: %s" % files)
        relevant_files = []
        for (action, filename) in files:
            if all(not filename.endswith(ext) for ext in self.extensions):
                continue
            relevant_files.append((action, filename))
        LOG.debug("FileProcessor: relevant files %s" % relevant_files)
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
                    LOG.debug("FileProcessor: event: %s" % event)
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
                    except Queue.Empty as e:
                        event = None
                if files:
                    # process the batch
                    self.scanfiles(files)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            LOG.warn("FileProcessor: Exception: %s" % str(e))
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

        fp = FileProcessor(
                self.watchdir,
                self.extensions,
                self.eventq,
                functools.partial(self.process))
        fprun = functools.partial(fp.run)
        self.processor = multiprocessing.Process(target=fprun)
        LOG.debug("FileWatcher: %s: starting" % self.name)
        self.processor.start()

    def action(self, event):
        # event.maskname, event.filename
        LOG.debug("FileWatcher: %s: event: %s" % (self.name, event))
        self.eventq.put(event)

    def process(self, files):
        # Override in child class
        LOG.debug("FileWatcher: %s: process: %s" % (
            self.name, files))

    def terminate(self, signum, frame):
        self.eventq.put(EOQ)
        if signum is not None:
            sys.exit(0)

    def run(self):
        signal.signal(signal.SIGINT, self.terminate)
        signal.signal(signal.SIGTERM, self.terminate)

        wm = pyinotify.WatchManager()
        handler = EventHandler(watcher=self, extensions=self.extensions)
        notifier = pyinotify.Notifier(wm, handler)
        wm.add_watch(self.watchdir, handler.events, rec=False)
        try:
            LOG.debug("FileWatcher: %s: notifier waiting ..." % self.name)
            notifier.loop()
        finally:
            LOG.debug("FileWatcher: %s: notifier returned" % self.name)
            self.terminate(None, None)

        LOG.debug("FileWatcher: %s: processor returned" % self.name)
        self.processor.join()
        return True


class TmpWatcher(FileWatcher):
    """Class for integration testing"""
    def __init__(self):
        filedir = "/tmp"
        extensions = EP_FILE_EXTENSION
        super(TmpWatcher, self).__init__(
            filedir, extensions, name="ep-watcher")

    def process(self, files):
        LOG.debug("TmpWatcher files: %s" % files)


class EpWatcher(FileWatcher):
    def __init__(self):
        filedir = cfg.CONF.OPFLEX.epg_mapping_dir
        extensions = EP_FILE_EXTENSION
        super(EpWatcher, self).__init__(
            filedir, extensions, name="ep-watcher")

    def get_addr(self, curr_ips):
        for i in curr_ips:
            del curr_ips[i]
            return i
        return None

    def process(self, files):
        LOG.debug("EP files: %s" % files)

        ipallocfile = STATE_FILE_NAME_FORMAT % STATE_IPADDR_ALLLOC
        ipallocfile = "%s/%s" % (MD_DIR, ipallocfile)

        curr_alloc = {}
        try:
            with open(ipallocfile, "r") as f:
                curr_alloc = jsonutils.load(f)
        except Exception as e:
            LOG.warn("EPwatcher: Exception in reading ipalloc: %s" % str(e))

        curr_ips = {}
        for i in xrange(1000):
            curr_ips[SVC_IP_BASE + i] = True
        for nnetwork in curr_alloc:
            thisip = netaddr.IPAddress(curr_alloc[nnetwork]['next-hop-ip'])
            del curr_ips[thisip.value]

        new_alloc = {}
        updated = False
        epfiledir = cfg.CONF.OPFLEX.epg_mapping_dir
        for filename in os.listdir(epfiledir):
            if not filename.endswith(EP_FILE_EXTENSION):
                continue

            ep = None
            filename = "%s/%s" % (epfiledir, filename)
            try:
                with open(filename, "r") as f:
                    ep = jsonutils.load(f)
            except Exception as e:
                LOG.warn("EPwatcher: Exception in reading %s: %s" %
                        (filename, str(e)))

            if ep:
                nnetwork = ep.get('neutron-network')
                vrf_name = ep.get('domain-name')
                vrf_tenant = ep.get('domain-policy-space')
                if nnetwork:
                    if nnetwork not in curr_alloc:
                        updated = True
                        as_uuid = nnetwork
                        as_addr = str(
                            netaddr.IPAddress(self.get_addr(curr_ips)))
                        new_alloc[nnetwork] = {
                            'neutron-network': nnetwork,
                            'domain-name': vrf_name,
                            'domain-policy-space': vrf_tenant,
                            'next-hop-ip': as_addr,
                            'uuid': as_uuid,
                        }
                    else:
                        new_alloc[nnetwork] = curr_alloc[nnetwork]
                        del curr_alloc[nnetwork]

        if curr_alloc:
            updated = True

        if updated:
            try:
                with open(ipallocfile, "w") as f:
                    jsonutils.dump(new_alloc, f)
            except Exception as e:
                LOG.warn("EPwatcher: Exception in writing ipalloc: %s" %
                    str(e))


class StateWatcher(FileWatcher):
    def __init__(self):
        self.mgr = AsMetadataManager(LOG)
        self.svc_ovs_port_mac = self.mgr.get_svc_ns_port_mac()[:17]

        filedir = MD_DIR
        extensions = STATE_FILE_EXTENSION
        super(StateWatcher, self).__init__(
            filedir, extensions, name="state-watcher")

    def process(self, files):
        LOG.debug("State Event: %s" % files)

        curr_alloc = {}
        ipallocfile = STATE_FILE_NAME_FORMAT % STATE_IPADDR_ALLLOC
        ipallocfile = "%s/%s" % (MD_DIR, ipallocfile)
        try:
            with open(ipallocfile, "r") as f:
                curr_alloc = jsonutils.load(f)
        except Exception as e:
            LOG.warn("StateWatcher: Exception in reading ipalloc: %s" %
                str(e))

        updated = False
        asfiledir = cfg.CONF.OPFLEX.as_mapping_dir
        for filename in os.listdir(asfiledir):
            if not filename.endswith(AS_FILE_EXTENSION):
                continue

            asvc = None
            try:
                with open(filename, "r") as f:
                    asvc = jsonutils.load(f)
            except Exception as e:
                LOG.warn("StateWatcher: Exception in reading %s: %s" %
                    (filename, str(e)))

            if asvc:
                nnetwork = asvc["neutron-network"]
                if nnetwork not in curr_alloc:
                    updated = True
                    self.as_del(filename, asvc)
                else:
                    if not self.as_equal(asvc, curr_alloc[nnetwork]):
                        updated = True
                        self.as_write(curr_alloc[nnetwork])
                    del curr_alloc[nnetwork]

        for nnetwork in curr_alloc:
            updated = True
            self.as_create(curr_alloc[nnetwork])

        if updated:
            self.mgr.update_supervisor()

    def as_equal(self, asvc, alloc):
        for idx in ["uuid", "neutron-network",
            "domain-name", "domain-policy-space"]:
            if asvc[idx] != alloc[idx]:
                return False
        if asvc["service-mapping"]["next-hop-ip"] != \
            alloc["next-hop-ip"]:
                return False
        return True

    def as_del(self, filename, asvc):
        try:
            self.mgr.del_ip(asvc["service-mapping"]["next-hop-ip"])
        except Exception as e:
            LOG.warn("EPwatcher: Exception in deleting IP: %s" %
                str(e))

        proxyfilename = PROXY_FILE_NAME_FORMAT % asvc["neutron-network"]
        proxyfilename = "%s/%s" % (MD_DIR, proxyfilename)
        try:
            os.remove(filename)
            os.remove(proxyfilename)
        except Exception as e:
            LOG.warn("EPwatcher: Exception in deleting file: %s" %
                str(e))

    def as_create(self, alloc):
        # nnetwork = alloc["neutron-network"]
        asvc = {
            "uuid": alloc["uuid"],
            "interface-name": SVC_OVS_PORT,
            "service-mac": self.svc_ovs_port_mac,
            "neutron-network": alloc["uuid"],
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
            LOG.warn("EPwatcher: Exception in adding IP: %s" %
                str(e))

        asfilename = AS_FILE_NAME_FORMAT % asvc["neutron-network"]
        asfilename = "%s/%s" % (AS_MAPPING_DIR, asfilename)
        try:
            with open(asfilename, "w") as f:
                jsonutils.dump(asvc, f)
        except Exception as e:
            LOG.warn("EPwatcher: Exception in writing services file: %s" %
                str(e))

        proxyfilename = PROXY_FILE_NAME_FORMAT % asvc["neutron-network"]
        proxyfilename = "%s/%s" % (MD_DIR, proxyfilename)
        proxystr = self.proxyconfig(alloc)
        try:
            with open(proxyfilename, "w") as f:
                f.write(proxystr)
        except Exception as e:
            LOG.warn("EPwatcher: Exception in writing proxy file: %s" %
                str(e))

    def proxyconfig(self, alloc):
        nnetwork = alloc["neutron-network"]
        ipaddr = alloc["next-hop-ip"]
        proxystr = """[program:apic-proxy-%s]
command=/sbin/ip netns exec of-svc /usr/bin/python /usr/bin/apic-ns-metadata-proxy --pid_file=/var/lib/neutron/external/pids/%s.pid --metadata_proxy_socket=/var/lib/neutron/metadata_proxy --network_id=%s --state_path=/var/lib/neutron --metadata_host %s --metadata_port=80 --log-file=proxy-%s.log --log-dir=/var/log/neutron
exitcodes=0,2
startsecs=10
startretries=3
stopwaitsecs=10
stdout_logfile=NONE
stderr_logfile=NONE
""" % (nnetwork, nnetwork, nnetwork, ipaddr, nnetwork[:8])  # noqa
        return proxystr


class AsMetadataManager(object):
    def __init__(self, logger):
        global LOG
        LOG = logger
        self.name = "AsMetadataManager"
        self.md_filename = "%s/%s" % (MD_DIR, MD_SUP_FILE_NAME)
        self.integ_bridge = cfg.CONF.OVS.integration_bridge
        self.initialized = False

    def init_all(self):
        self.init_host(self.integ_bridge)
        self.init_supervisor()
        self.start_supervisor()
        return

    def ensure_initialized(self):
        if not self.initialized:
            try:
                self.clean_as_files()
                self.init_all()
                self.initialized = True
            except Exception as e:
                LOG.error("%s: in initializing anycast metadata service: %s" %
                    (self.name, str(e)))

    def ensure_terminated(self):
        if self.initialized:
            try:
                self.initialized = False
                self.clean_as_files()
                self.stop_supervisor()
            except Exception as e:
                LOG.error("%s: in shuttingdown anycast metadata service: %s" %
                    (self.name, str(e)))

    def sh(self, cmd):
        # TODO(mandeep): Use root_helper
        cmd = "sudo %s" % cmd
        LOG.debug("%s: Running command: %s" % (
            self.name, cmd))
        ret = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, shell=True)
        LOG.debug("%s: Command output: %s" % (
            self.name, ret))
        return ret

    def write_file(self, name, data):
        LOG.debug("%s: Writing file: name=%s, data=%s" % (
            self.name, name, data))
        with open(name, "w") as f:
            f.write(data)

    def clean_as_files(self):
        for filename in os.listdir(AS_MAPPING_DIR):
            os.remove(filename)

    def start_supervisor(self):
        self.sh("supervisord -c %s" % self.md_filename)

    def update_supervisor(self):
        self.sh("supervisorctl -c %s reread" % self.md_filename)
        self.sh("supervisorctl -c %s update" % self.md_filename)

    def reload_supervisor(self):
        self.sh("supervisorctl -c %s reload" % self.md_filename)

    def stop_supervisor(self):
        self.sh("supervisorctl -c %s shutdown" % self.md_filename)

    def add_default_route(self, nexthop):
        self.sh("ip netns exec %s ip route add default via %s" %
                (SVC_NS, nexthop))

    def add_ip(self, ipaddr):
        self.sh("ip netns exec %s ip addr add %s/%s dev %s" %
                (SVC_NS, ipaddr, SVC_IP_CIDR, SVC_NS_PORT))

    def del_ip(self, ipaddr):
        self.sh("ip netns exec %s ip addr del %s/%s dev %s" %
                (SVC_NS, ipaddr, SVC_IP_CIDR, SVC_NS_PORT))

    def get_svc_ns_port_mac(self):
        return self.sh("ip netns exec %s ip link show %s | "
            "awk -e '/link\/ether/ {print $2}'" %
            (SVC_NS, SVC_NS_PORT))

    def init_host(self, integ_br):
        # Create required directories
        self.sh("mkdir -p %s" % PID_DIR)
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
            self.sh("ovs-vsctl add-port %s %s" %
                    (integ_br, SVC_OVS_PORT))
            self.add_ip(SVC_IP_DEFAULT)
            self.add_default_route(SVC_NEXTHOP)
            self.sh("ethtool --offload %s tx off" % SVC_OVS_PORT)
            self.sh("ip netns exec %s ethtool --offload %s tx off" %
                    (SVC_NS, SVC_NS_PORT))

    def init_supervisor(self):
        config_str = """[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[unix_http_server]
file=/var/run/md-svc-supervisor.sock

[supervisorctl]
serverurl=unix:///var/run/md-svc-supervisor.sock

[supervisord]
identifier = md-svc-supervisor
pidfile = /var/run/md-svc-supervisor.pid
logfile = /var/log/neutron/metadata-supervisor.log
logfile_maxbytes = 10MB
logfile_backups = 3
loglevel = debug
childlogdir = /var/log/neutron
umask = 022
minfds = 1024
minprocs = 200
nodaemon = false
nocleanup = false
strip_ansi = false

[program:metadata-agent]
command=/usr/bin/neutron-metadata-agent --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/metadata_agent.ini --config-dir /etc/neutron/metadata_agent.ini --log-file /var/log/neutron/metadata-agent.log
exitcodes=0,2
startsecs=10
startretries=3
stopwaitsecs=10
stdout_logfile=NONE
stderr_logfile=NONE

[program:metadata-ep-watcher]
command=/usr/bin/opflex-metadata-ep-watcher --config-file /etc/neutron/neutron.conf --log-file /var/log/neutron/metadata-ep-watcher.log
exitcodes=0,2
startsecs=10
startretries=3
stopwaitsecs=10
stdout_logfile=NONE
stderr_logfile=NONE

[program:metadata-state-watcher]
command=/usr/bin/opflex-metadata-state-watcher --config-file /etc/neutron/neutron.conf --log-file /var/log/neutron/metadata-state-watcher.log
exitcodes=0,2
startsecs=10
startretries=3
stopwaitsecs=10
stdout_logfile=NONE
stderr_logfile=NONE

[include]
files = %s/*.proxy
""" % MD_DIR  # noqa
        config_file = "%s/%s" % (MD_DIR, MD_SUP_FILE_NAME)
        self.write_file(config_file, config_str)


def init_env():
    # importing ovs_config got OVS registered
    cfg.CONF.register_opts(gbp_opts, "OPFLEX")
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
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


if __name__ == "__main__":
    tmp_watcher_main()
