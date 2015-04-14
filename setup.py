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
# @author: Ivar Lazzaro (ivar-lazzaro), Cisco Systems Inc.

import setuptools


setuptools.setup(
    name="python-opflex-agent",
    version="2.0.0",
    packages=setuptools.find_packages(exclude=["*.tests", "*.tests.*",
                                               "tests.*", "tests"]),
    author="Cisco Systems, Inc.",
    author_email="apicapi@noironetworks.com",
    url="http://github.com/noironetworks/python-opflex-agent/",
    license="http://www.apache.org/licenses/LICENSE-2.0",
    description="This neutron agent provides edge policy enforcement.",
    entry_points={
        'console_scripts': [
            'openstack-opflex-agent = opflexagent.gbp_ovs_agent:main'],
        'neutron.ml2.type_drivers': [
            'opflex = opflexagent.type_opflex:OpflexTypeDriver']
    }
)
