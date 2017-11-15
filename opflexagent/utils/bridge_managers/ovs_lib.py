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

import contextlib

from neutron.agent.common import ovs_lib
from neutron.agent.ovsdb import impl_vsctl


class OVSBridge(ovs_lib.OVSBridge):

    def reset_ofversion(self):
        context = self.ovsdb.context
        return impl_vsctl.BaseCommand(context, 'set',
                                      args=[self.br_name, 'protocols=[]'])

    @contextlib.contextmanager
    def ovsdb_transaction(self):
        """Context manager for ovsdb transaction.

        The object caches whether its already in transaction and if it is, the
        original transaction is returned.  This behavior enables calling
        manager several times while always getting the same transaction.
        """
        try:
            if self._transaction:
                yield self._transaction
        except AttributeError:
            pass
        else:
            with self.ovsdb.transaction() as txn:
                self._transaction = txn
                try:
                    yield txn
                finally:
                    self._transaction = None
