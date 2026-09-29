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

from opflexagent.vpplib import hook


class _FakeProc(object):
    def __init__(self, returncode=None):
        self.returncode = returncode

    def poll(self):
        return self.returncode


class _FakeCase(object):
    def __init__(self):
        self.logger = mock.Mock()
        self.vpp_bin = '/usr/bin/vpp'
        self.tempdir = '/tmp'
        self.vpp_dead = False
        self.vpp = _FakeProc(None)


class TestVpplibHook(base.BaseTestCase):

    def test_fix_string_and_base_hook(self):
        self.assertEqual('', hook.fix_string(b'abc\0rest'))
        self.assertEqual('', hook.fix_string(object()))

        logger = mock.Mock()
        hk = hook.Hook(logger)
        hk.before_api('api', {'a': 1})
        hk.after_api('api', {'a': 1})
        hk.before_cli('show version')
        hk.after_cli('show version')

        self.assertEqual(3, logger.debug.call_count)

    def test_poll_hook_states(self):
        tc = _FakeCase()
        ph = hook.PollHook(tc)

        tc.vpp_dead = True
        ph.poll_vpp()

        tc.vpp_dead = False
        tc.vpp = _FakeProc(None)
        ph.poll_vpp()

        tc.vpp = _FakeProc(-15)
        with mock.patch.object(hook.os.path, 'isfile',
                       return_value=True), \
                mock.patch.object(ph, 'on_crash') as on_crash:
            self.assertRaises(hook.VppDiedError, ph.poll_vpp)
            on_crash.assert_called_once_with('/tmp/core')
            self.assertTrue(tc.vpp_dead)

    def test_poll_hook_before_calls(self):
        tc = _FakeCase()
        ph = hook.PollHook(tc)
        ph.LOG = tc.logger
        with mock.patch.object(ph, 'poll_vpp') as poll:
            ph.before_api('api', {'k': 'v'})
            ph.before_cli('show int')
        self.assertEqual(2, poll.call_count)

    def test_step_hook_skip_and_user_input(self):
        tc = _FakeCase()
        sh = hook.StepHook(tc)

        self.assertFalse(sh.skip())

        stack = [
            ('/tmp/a.py', 10, 'f0', 'line0'),
            ('/tmp/b.py', 20, 'f1', 'line1'),
        ]
        sh.skip_stack = stack
        sh.skip_num = 1
        with mock.patch.object(hook.traceback, 'extract_stack',
                       return_value=stack):
            self.assertTrue(sh.skip())
            self.assertEqual(1, sh.skip_count)

        mismatch = [
            ('/tmp/a.py', 10, 'f0', 'line0'),
            ('/tmp/c.py', 30, 'f2', 'line2'),
        ]
        with mock.patch.object(hook.traceback, 'extract_stack',
                       return_value=mismatch):
            self.assertFalse(sh.skip())
            self.assertIsNone(sh.skip_stack)
            self.assertIsNone(sh.skip_num)

        with mock.patch.object(hook.traceback, 'extract_stack',
                       return_value=stack), \
            mock.patch.object(hook.six, 'input',
                      side_effect=['bad', '99', '1']):
            sh.user_input()
            self.assertEqual(1, sh.skip_num)
            self.assertEqual(stack, sh.skip_stack)

    def test_step_hook_before_api_and_cli_paths(self):
        tc = _FakeCase()
        sh = hook.StepHook(tc)

        with mock.patch.object(sh, 'skip', return_value=True), \
                mock.patch.object(sh, 'user_input') as ui, \
                mock.patch.object(hook.PollHook, 'before_api') as p_api, \
                mock.patch.object(hook.PollHook, 'before_cli') as p_cli:
            sh.before_api('api', {'a': 1})
            sh.before_cli('show')
            ui.assert_not_called()
            p_api.assert_called_once_with('api', {'a': 1})
            p_cli.assert_called_once_with('show')

        with mock.patch.object(sh, 'skip', return_value=False), \
                mock.patch.object(sh, 'user_input') as ui, \
                mock.patch.object(hook.PollHook, 'before_api'), \
                mock.patch.object(hook.PollHook, 'before_cli'):
            sh.before_api('api2', {'b': 2})
            sh.before_cli('show2')
            self.assertEqual(2, ui.call_count)
