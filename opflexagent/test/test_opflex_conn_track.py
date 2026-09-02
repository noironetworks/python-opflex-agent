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

from unittest import mock

from neutron.tests import base

from opflexagent import opflex_conn_track


class TestOpflexConnTrack(base.BaseTestCase):

    def test_logger_starts_conntrack_and_logger_processes(self):
        p1 = mock.Mock(stdout='stdout')
        p2 = mock.Mock()
        with mock.patch('subprocess.Popen', side_effect=[p1, p2]) as popen:
            wrapper = opflex_conn_track.SnatConntrackLogger('cmd1', 'cmd2')

        self.assertEqual(p1, wrapper.p1)
        self.assertEqual(p2, wrapper.p2)
        popen.assert_has_calls([
            mock.call('cmd1', stdout=opflex_conn_track.subprocess.PIPE,
                      stderr=opflex_conn_track.subprocess.STDOUT,
                      close_fds=True, shell=True),
            mock.call('cmd2', stdin='stdout', close_fds=True, shell=True)])

    def test_logger_handles_popen_exception(self):
        with mock.patch('subprocess.Popen', side_effect=OSError('boom')):
            wrapper = opflex_conn_track.SnatConntrackLogger('cmd1', 'cmd2')
        self.assertIsNone(wrapper.p1)
        self.assertIsNone(wrapper.p2)

    def test_kill_child_procs_terminates_available_processes(self):
        wrapper = opflex_conn_track.SnatConntrackLogger.__new__(
            opflex_conn_track.SnatConntrackLogger)
        wrapper.p1 = mock.Mock(returncode=None)
        wrapper.p2 = mock.Mock(returncode=None)
        wrapper._kill_child_procs()
        wrapper.p1.terminate.assert_called_once_with()
        wrapper.p2.terminate.assert_called_once_with()

    def test_terminate_exits_with_negative_signal(self):
        wrapper = opflex_conn_track.SnatConntrackLogger.__new__(
            opflex_conn_track.SnatConntrackLogger)
        with mock.patch.object(wrapper, '_kill_child_procs') as kill, \
                mock.patch('sys.exit', side_effect=SystemExit) as sys_exit:
            self.assertRaises(SystemExit, wrapper.terminate, 15, None)
        kill.assert_called_once_with()
        sys_exit.assert_called_once_with(-15)

    def test_wait_registers_handlers_and_returns_restart_code(self):
        wrapper = opflex_conn_track.SnatConntrackLogger.__new__(
            opflex_conn_track.SnatConntrackLogger)
        wrapper.p1 = mock.Mock()
        wrapper.p2 = mock.Mock()
        wrapper.p1.poll.side_effect = [None, 0]
        wrapper.p2.poll.return_value = None
        with mock.patch('signal.signal') as signal_func, \
                mock.patch('time.sleep') as sleep, \
                mock.patch.object(wrapper, '_kill_child_procs') as kill:
            result = wrapper.wait()
        self.assertEqual(-opflex_conn_track.signal.SIGTERM, result)
        self.assertEqual(2, signal_func.call_count)
        sleep.assert_called_once_with(1)
        kill.assert_called_once_with()

    def test_main_builds_commands_and_waits(self):
        logger = mock.Mock()
        logger.wait.return_value = -15
        with mock.patch(
            'opflexagent.opflex_conn_track.config.setup_logging'), \
                mock.patch('opflexagent.opflex_conn_track.comm_utils.'
                           'log_opt_values'), \
                mock.patch('opflexagent.opflex_conn_track.sys.argv',
                           ['prog', 'ns1', 'local0', 'info']), \
                mock.patch('opflexagent.opflex_conn_track.SnatConntrackLogger',
                           return_value=logger) as logger_cls:
            self.assertEqual(-15, opflex_conn_track.main())
        logger_cls.assert_called_once_with(
            'ip netns exec ns1 conntrack -E -o timestamp',
            'logger -p local0.info -t opflex-conn-track')
