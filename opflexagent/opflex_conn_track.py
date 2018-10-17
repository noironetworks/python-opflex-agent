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

import subprocess
import sys

from neutron.common import config
from neutron.common import utils as comm_utils
from oslo_log import log


LOG = log.getLogger(__name__)


def sh(cmd):
    LOG.debug("conn_track: Running command: %s" % cmd)
    ret = ''
    try:
        ret = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        LOG.error("In running command: %s: %s" % (cmd, str(e)))
    LOG.debug("conn_track: Command output: %s" % ret)
    return ret


# This program takes 3 parameters,
# 1st is the SNAT network namespace name.
# 2nd is the syslog facility name.
# 3rd is the syslog severity level.
def main():
    config.setup_logging()
    comm_utils.log_opt_values(LOG)
    command = ("ip netns exec %s conntrack -E -o timestamp 2>&1 | logger "
               "-p %s.%s -t opflex-conn-track") % (
                   sys.argv[1], sys.argv[2], sys.argv[3])
    LOG.debug("conn_track command: %s" % command)
    sh(command)

    return


if __name__ == "__main__":
    main()
