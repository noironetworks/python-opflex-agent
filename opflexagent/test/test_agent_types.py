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

import mock

from opflexagent import gbp_agent
from opflexagent.test import base

from oslo_config import cfg


class TestGBPOpflexAgentTypes(base.OpflexTestBase):

    def setUp(self):
        super(TestGBPOpflexAgentTypes, self).setUp()
        cfg.CONF.set_default('quitting_rpc_timeout', 10, 'AGENT')
        # UTs will hang when run from tox w/o this
        self.signal_patch = mock.patch('signal.signal')
        self.signal_patch.start()

    def tearDown(self):
        super(TestGBPOpflexAgentTypes, self).tearDown()
        self.signal_patch.stop()

    def test_opflex_agent_mode(self):
        opflex_agent = mock.patch('opflexagent.gbp_agent.GBPOpflexAgent')
        opflex_patch = opflex_agent.start()
        metadata_mgr = mock.patch(
            'opflexagent.as_metadata_manager.AsMetadataManager')
        metadata_patch = metadata_mgr.start()
        cfg.CONF.set_override('agent_mode', 'opflex', 'OPFLEX')
        with mock.patch('os.path.basename'):
            with mock.patch('sys.argv'):
                gbp_agent.main()
                self.assertEqual(1, opflex_patch.call_count)
                self.assertEqual(1, metadata_patch.call_count)
        opflex_agent.stop()
        metadata_mgr.stop()

    def test_dvs_agent_mode(self):
        mock_dvs_instance = mock.MagicMock()
        import_mock = mock.patch('importlib.import_module',
                                 return_value=mock_dvs_instance)
        import_patch = import_mock.start()
        cfg.CONF.set_override('agent_mode', 'dvs', 'OPFLEX')
        with mock.patch('os.path.basename'):
            with mock.patch('sys.argv'):
                gbp_agent.main()
                self.assertEqual(1, import_patch.call_count)
                self.assertEqual(
                    1, mock_dvs_instance.create_agent_config_map.call_count)
        import_mock.stop()

    def test_dvs_agent_no_binding_mode(self):
        mock_dvs_instance = mock.MagicMock()
        import_mock = mock.patch('importlib.import_module',
                                 return_value=mock_dvs_instance)
        import_patch = import_mock.start()
        cfg.CONF.set_override('agent_mode', 'dvs_no_binding', 'OPFLEX')
        with mock.patch('os.path.basename'):
            with mock.patch('sys.argv'):
                gbp_agent.main()
                self.assertEqual(1, import_patch.call_count)
                self.assertEqual(
                    1, mock_dvs_instance.create_agent_config_map.call_count)
        import_mock.stop()

    def test_dvs_agent_mode_no_package(self):
        import_mock = mock.patch('importlib.import_module',
                                 side_effect=ValueError)
        import_patch = import_mock.start()
        cfg.CONF.set_override('agent_mode', 'dvs', 'OPFLEX')
        with mock.patch('os.path.basename'):
            with mock.patch('sys.argv'), mock.patch('sys.exit') as sys_patch:
                try:
                    gbp_agent.main()
                except AttributeError:
                    self.assertEqual(1, sys_patch.call_count)
                self.assertEqual(1, import_patch.call_count)
        import_mock.stop()
