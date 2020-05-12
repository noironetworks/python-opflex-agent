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

from contextlib2 import ExitStack, contextmanager
from neutron_lib.utils import runtime
from opflexagent.utils.bridge_managers import (
    bridge_manager_base as bridge_manager)
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def get_bridge_manager(conf):
    """Get Bridge Manager.

    :param conf: bridge manager configuration object
    :raises SystemExit of 1 if driver cannot be loaded
    """

    try:
        loaded_class = runtime.load_class_by_alias_or_classname(
                bridge_manager.BRIDGE_MANAGER_NAMESPACE, conf.bridge_manager)
        return loaded_class()
    except ImportError:
        LOG.error("Error loading bridge manager '%s'",
                  conf.bridge_manager)
        raise SystemExit(1)


@contextmanager
def nested_context_manager(*contexts):
    """
    The new Python 3 contextlib.ExitStack class was
    added as a replacement for contextlib.nested()
    Used to combine other context managers.

    :param contexts: list of context managers
    """
    with ExitStack() as stack:
        for ctx in contexts:
            stack.enter_context(ctx)
        yield contexts
