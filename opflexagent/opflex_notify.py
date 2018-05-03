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

import json
import multiprocessing
import os.path
import socket
import struct
import sys
import time

from neutron.common import config
from neutron.common import utils
from neutron_lib import context
from opflexagent import config as ofcfg  # noqa
from opflexagent import rpc
from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class OpflexNotifyAgent(object):
    def __init__(self):
        self.host = cfg.CONF.host
        self.agent_id = 'opflex-notify-agent-%s' % self.host
        self.context = context.get_admin_context_without_session()
        self.sockname = cfg.CONF.OPFLEX.opflex_notify_socket_path
        self.of_rpc = rpc.GBPServerRpcApi(rpc.TOPIC_OPFLEX)

    def _handle(self, uuids, mac, addr):
        LOG.debug('Handle: endpoint(s): {}, mac: {}, addr: {}'.
            format(uuids, mac, addr))
        try:
            for uuid in uuids:
                uuid = uuid.split('|')[0]
                if not uuid:
                    continue
                notification = {
                    'port': uuid,
                    'ip_address_v4': addr,
                    'mac': mac,
                }
                LOG.debug('Handle: notification: {}'.format(notification))
                self.of_rpc.ip_address_owner_update(
                    self.context, self.agent_id,
                    notification, host=self.host)
        except Exception as e:
            # skip this notification, but don't kill daemon
            LOG.error('Handle: In sending RPC: {}'.format(e))

    def _connect(self):
        name = self.sockname
        LOG.info('Connect: Connecting: {}'.format(name))

        client = None
        if os.path.exists(name):
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(name)
                LOG.info('Connect: Connected: {}'.format(name))

                subscribe = {
                    'method': 'subscribe',
                    'params': {
                        'type': [
                            'virtual-ip',
                        ],
                    },
                }
                msg = bytearray(json.dumps(subscribe))
                msg_len = socket.htonl(len(msg))
                client.send(struct.pack('I', msg_len))
                client.send(msg)
                LOG.info('Connect: Established: {}'.format(name))
            except Exception as e:
                # set client to None, but don't kill daemon
                LOG.error('Connect: In connecting to {}: {}'.format(name, e))
                if client is not None:
                    client.close()
                client = None
        else:
            LOG.error('Connect: No such file: {}'.format(name))

        return client

    def _read_msg(self, client):
        LOG.debug('Read: Waiting for notification ...')

        notification = None
        try:
            data = client.recv(4)
            if (len(data) < 4):
                raise ValueError('Unexpected end-of-file')

            msg_len = socket.ntohl(struct.unpack('I', data)[0])
            msg = client.recv(msg_len)
            if (len(msg) < msg_len):
                raise ValueError('Unexpected message length {} (msg_len {})'.
                    format(len(msg), msg_len))

            notif = json.loads(msg)
            if ('method' not in notif or 'params' not in notif):
                raise ValueError('Unexpected message {}'.format(notif))

            if (notif['method'] == 'virtual-ip'):
                p = notif['params']
                if ('uuid' in p and 'mac' in p and 'ip' in p):
                    notification = (p['uuid'], p['mac'], p['ip'])

        except ValueError as ve:
            LOG.error('Read: Could not decode message: {}'.format(ve))
        except Exception as e:
            LOG.error('Read: In reading notification: {}'.format(e))

        LOG.debug('Read: Notification: {}'.format(notification))
        return notification

    def _throttle(self):
        LOG.debug('Trrottle ...')
        try:
            time.sleep(1)  # throttle to less than 1 update/sec
        except Exception as e:
            LOG.warning('Throttle: {}'.format(e))

    def _exit(self, client):
        if client is not None:
            try:
                LOG.debug('Exit: Close client')
                client.close()
            except Exception as e:
                LOG.warning(e)
        LOG.info('Exit: Opflex Notification Agent')
        sys.exit(0)

    def run(self):
        """Infinite loop which catches all exception, exits on ^C"""

        # Don't bother running if we don't have a socket
        if not self.sockname:
            LOG.warning("Notification socket not set, "
                        "notifications will not be sent")
            return

        while True:
            try:
                client = self._connect()
                if client is not None:
                    while True:
                        msg = self._read_msg(client)
                        if msg is not None:
                            self._handle(*msg)
                            self._throttle()
                        else:
                            # unexpected msg, exit inner loop
                            break
                    LOG.debug('Run: Close client')
                    client.close()
                # Don't re-try too quickly
                self._throttle()
            except KeyboardInterrupt:
                self._exit(client)
            except Exception as e:
                LOG.error('Run: {}'.format(e))


def worker(initconfig=False, daemon=True):
    class OpflexNotifyWorker(multiprocessing.Process):
        def __init__(self):
            self.agent = None
            super(OpflexNotifyWorker, self).__init__()

        def run(self):
            self.agent = OpflexNotifyAgent()
            self.agent.run()
            return

    worker = None
    try:
        if initconfig:
            config.init(sys.argv[1:])
            config.setup_logging()
            utils.log_opt_values(LOG)

        worker = OpflexNotifyWorker()
        worker.daemon = daemon
        worker.start()
    except Exception as e:
        LOG.error('Worker Initalization: {}'.format(e))
    return worker


def main():
    worker(initconfig=True, daemon=False)
    return


if __name__ == "__main__":
    main()
