#!/usr/bin/env python
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

import signal
import subprocess  # nosec
import sys
import time

from neutron.common import config
from neutron.common import utils as comm_utils
from oslo_log import log


LOG = log.getLogger(__name__)


class SnatConntrackLogger(object):
    """Opflex SNAT Connection Tracking Logger

    This class dumps the output of connection tracking events
    for a Linux network namespace used to perform SNAT on hosts
    running the neutron-opflex-agent. This class is created in
    order to spawn two processes per namespace: one to run a
    connection tracker in the Linux network namespace, and the
    other to collect the standard output and dump it into syslog,
    using the log level and facility set in a configuration file.
    The process for this is managed using supervisord, which in
    version 4.0 or later supports redirecting stdout and stderr
    to syslog. However, older Linux distributions ship with
    supervisord versions older than this, so the logger tool
    must be used for this redirection. While supervisord can
    handle the lifecycle of the top level process, this class
    neededs manage the lifecycle of the child prcoesses that
    are spawned (i.e. conntrack and logger), ensuring that
    the parent exit code is set correctly so that supervisord
    can handle any respawning, if needed.

    REVISIT: Should have some sort of pooling to avoid exhaustion
    """
    def __init__(self, conntrack_cmd, logger_cmd):
        self.ret = None
        self.p1 = self.p2 = None
        try:
            # Conntrack process redirects stderr to stdout,
            # returned Popen has file object for stdout
            self.p1 = subprocess.Popen(
                conntrack_cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, close_fds=True, shell=True)  # nosec
            # Logger uses stdout member from conntrack process for its stdin
            self.p2 = subprocess.Popen(
                logger_cmd, stdin=self.p1.stdout,
                close_fds=True, shell=True)  # nosec
        except Exception as e:
            LOG.error("In running commands: %(cmds)s: %(exc)s",
                      {'cmds': conntrack_cmd + logger_cmd, 'exc': str(e)})

    def _kill_child_procs(self):
        for proc in [self.p1, self.p2]:
            LOG.debug("conn_track: proc: %s", proc.returncode)
            try:
                proc.terminate()
            except Exception as e:
                LOG.info("Exception occurred while killing child processes."
                         " error: %s", str(e))

    def terminate(self, signum, frame):
        self._kill_child_procs()
        LOG.debug("conn_track: returning %s", -signum)
        sys.exit(-signum)

    def wait(self):
        # REVISIT: We probably should consider whether we
        #          should be checking for other signals,
        #          such as SIGPIPE. The assumption is that
        #          anything uncaught could result in a child
        #          process not getting terminated, and left
        #          as a zombie process
        signal.signal(signal.SIGINT, self.terminate)
        signal.signal(signal.SIGTERM, self.terminate)
        while (self.p1 and self.p2) and (self.p1.poll() is None and
                                         self.p2.poll() is None):
            time.sleep(1)

        self._kill_child_procs()
        # NOTE: The assumption here is that this process is always
        #       being managed by supervisord. In this case, we always
        #       return a non-zero RC, as we want supervisord to restart
        #       us whenever we die, regardless of the reason.
        return -signal.SIGTERM


# This program takes 3 parameters,
# 1st is the SNAT network namespace name.
# 2nd is the syslog facility name.
# 3rd is the syslog severity level.
def main():
    config.setup_logging()
    comm_utils.log_opt_values(LOG)
    cmd1 = ("ip netns exec %s conntrack -E -o timestamp") % (sys.argv[1])
    cmd2 = ("logger -p %s.%s -t opflex-conn-track") % (sys.argv[2],
                                                       sys.argv[3])
    LOG.debug("conn_track command: %s", cmd1)
    LOG.debug("logger command: %s", cmd2)
    wrapper = SnatConntrackLogger(cmd1, cmd2)
    return wrapper.wait()


if __name__ == "__main__":
    ret = main()
    LOG.debug("conn_track: returning %s", ret)
    sys.exit(ret)
