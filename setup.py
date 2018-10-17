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
#

import setuptools


setuptools.setup(
    name="neutron-opflex-agent",
    version="7.3.2",
    packages=setuptools.find_packages(exclude=["*.tests", "*.tests.*",
                                               "tests.*", "tests"]),
    author="Cisco Systems, Inc.",
    author_email="apicapi@noironetworks.com",
    url="http://github.com/noironetworks/python-opflex-agent/",
    license="http://www.apache.org/licenses/LICENSE-2.0",
    description="This neutron agent provides edge policy enforcement.",
    entry_points={
        'console_scripts': [
            'neutron-opflex-agent = '
                'opflexagent.gbp_agent:main',
            'opflex-ep-watcher = '
                'opflexagent.as_metadata_manager:ep_watcher_main',
            'opflex-state-watcher = '
                'opflexagent.as_metadata_manager:state_watcher_main',
            'neutron-cisco-apic-host-agent = '
                'opflexagent.apic_topology:agent_main',
            'opflex-ns-proxy = '
                'opflexagent.namespace_proxy:main',
            'opflex-conn-track = '
                'opflexagent.opflex_conn_track:main',
        ],
        'neutron.ml2.type_drivers': [
            'opflex = opflexagent.type_opflex:OpflexTypeDriver',
        ],
        'opflexagent.utils.bridge_managers': [
            'ovs = opflexagent.utils.bridge_managers.ovs_manager:OvsManager',
            'fake = opflexagent.utils.bridge_managers.ovs_manager:FakeManager',
            'vpp = opflexagent.utils.bridge_managers.vpp_manager:VppManager'
        ],
        'os_vif': [
            'vpp = opflexagent.vif_plug_vpp.vpp:VppPlugin',
        ]
    },
    data_files=[('etc/neutron/opflex-agent',
        ['etc/neutron/opflex-agent/apic_topology_service.ini'])]
)
