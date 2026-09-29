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

import collections
import importlib
import json
import os
import sys

from unittest import mock

from neutron.tests import base


def tearDownModule():
    parent = sys.modules.get('opflexagent')
    if parent is not None and hasattr(parent, 'vpplib'):
        delattr(parent, 'vpplib')
    for name in ['opflexagent.vpplib.VPPApi',
                 'opflexagent.vpplib.vpp_papi_provider',
                 'opflexagent.vpplib',
                 'hook']:
        sys.modules.pop(name, None)


class TestVpplib(base.BaseTestCase):

    def _load_vpplib(self):
        os.environ['NO_VPP_PAPI'] = '1'
        vpplib_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', 'vpplib'))
        if vpplib_path not in sys.path:
            sys.path.insert(0, vpplib_path)
        parent = sys.modules.get('opflexagent')
        if parent is not None and hasattr(parent, 'vpplib'):
            delattr(parent, 'vpplib')
        for name in ['opflexagent.vpplib.VPPApi',
                     'opflexagent.vpplib.vpp_papi_provider',
                     'opflexagent.vpplib',
                     'hook']:
            sys.modules.pop(name, None)
        importlib.invalidate_caches()
        provider = importlib.import_module(
            'opflexagent.vpplib.vpp_papi_provider')
        vppapi = importlib.import_module('opflexagent.vpplib.VPPApi')
        return provider, vppapi

    def test_vppapi_helpers_parse_reply_data(self):
        provider, vppapi = self._load_vpplib()
        api = vppapi.VPPApi(mock.Mock(), 'client')
        reply = collections.namedtuple('Reply', ['value'])(7)

        self.assertEqual('abc', vppapi.VPPApi._fix_tag(b'abc\0def'))
        self.assertEqual('10.0.0.1', vppapi.VPPApi._fix_v4_addr(
            b'\x0a\x00\x00\x01'))
        self.assertEqual('aa:bb:cc', vppapi.VPPApi._fix_l2_addr(
            b'\xaa\xbb\xcc', 3))
        self.assertEqual('tap0', vppapi.VPPApi._fix_string(b'tap0\0\0'))
        self.assertEqual([{'value': 7}],
                         vppapi.VPPApi._fix_tuplelist([reply]))
        self.assertEqual({'value': 7},
                         json.loads(api._handle_reply(reply)))
        self.assertEqual([{'value': 7}],
                         json.loads(api._handle_reply([reply])))
        self.assertEqual([], json.loads(api._handle_mac([])))
        hook = importlib.import_module('hook')
        self.assertEqual('', hook.fix_string(object()))

    def test_vppapi_vhost_status_helpers(self):
        provider, vppapi = self._load_vpplib()
        data = json.dumps([
            {'sock_filename': '/tmp/a', 'sock_errno': 0, 'num_regions': 1,
             'interface_name': 'VirtualEthernet0'},
            {'sock_filename': '/tmp/b', 'sock_errno': 1, 'num_regions': 1,
             'interface_name': 'VirtualEthernet1'},
            {'sock_filename': '/tmp/c', 'sock_errno': 0, 'num_regions': 0,
             'interface_name': 'VirtualEthernet2'}])
        self.assertEqual((1, ''), vppapi.VPPApi._get_vhost_status(
            data, '/tmp/missing'))
        self.assertEqual((2, ''), vppapi.VPPApi._get_vhost_status(
            data, '/tmp/b'))
        self.assertEqual((4, ''), vppapi.VPPApi._get_vhost_status(
            data, '/tmp/c'))
        status, vhost = vppapi.VPPApi._get_vhost_status(data, '/tmp/a')
        self.assertEqual(0, status)
        self.assertEqual('VirtualEthernet0', vhost['interface_name'])
        self.assertEqual(set(['VirtualEthernet0', 'VirtualEthernet1',
                              'VirtualEthernet2']),
                         vppapi.VPPApi._get_vhost_set(data))
        self.assertEqual(set(['aa:bb']), vppapi.VPPApi._get_vhost_mac_set(
            json.dumps([{'interface_name': 'VirtualEthernet0',
                         'l2_address': 'aa:bb'},
                        {'interface_name': 'host-tap0',
                         'l2_address': 'cc:dd'}])))
        self.assertEqual(0xaabbccddeeff0000,
                         provider.VppPapiProvider._convert_mac(
                             None, 'aa:bb:cc:dd:ee:ff'))

    def test_vpp_papi_provider_api_cli_and_events(self):
        provider, vppapi = self._load_vpplib()

        class FakeVPP(object):
            def __init__(self, *args, **kwargs):
                self.api = mock.Mock()
                self.api.cli_inband.return_value = mock.Mock(
                    reply=b'ok\0')

            def connect(self, name, shm_prefix):
                self.name = name
                self.shm_prefix = shm_prefix
                return 0

            def disconnect(self):
                self.disconnected = True

            def register_event_callback(self, callback):
                self.callback = callback

        provider.VPP = FakeVPP
        papi = provider.VppPapiProvider('client', shm_prefix='shm')
        self.assertEqual(0, papi.connect())
        self.assertEqual('ok', papi.cli('show version'))
        event = mock.Mock()
        papi('event', event)
        self.assertEqual(event, papi.wait_for_event(0.1))
        papi('event', event)
        self.assertEqual([event], list(papi.collect_events()))
        hook = mock.Mock()
        papi.register_hook(hook)
        api_fn = mock.Mock(__name__='api_fn', return_value=mock.Mock(retval=0))
        self.assertEqual(api_fn.return_value, papi.api(api_fn, {'arg': 1}))
        hook.before_api.assert_called_once_with('api_fn', {'arg': 1})
        hook.after_api.assert_called_once_with('api_fn', {'arg': 1})
        with papi.expect_negative_api_retval():
            neg_fn = mock.Mock(__name__='neg_fn',
                               return_value=mock.Mock(retval=-1))
            self.assertEqual(neg_fn.return_value, papi.api(neg_fn, {}))
        with self.assertRaisesRegex(Exception, 'Event did not occur'):
            papi.wait_for_event(0)
        papi.disconnect()

    def test_vpp_papi_provider_common_wrappers(self):
        provider, vppapi = self._load_vpplib()
        papi = provider.VppPapiProvider.__new__(provider.VppPapiProvider)
        papi.api = mock.Mock(side_effect=lambda fn, args, *a, **k: (fn, args))
        papi.papi = mock.Mock()

        self.assertEqual((papi.papi.show_version, {}), papi.show_version())
        self.assertEqual((papi.papi.pg_create_interface,
                          {'interface_id': 3}),
                         papi.pg_create_interface(3))
        self.assertEqual((papi.papi.sw_interface_dump,
                          {'name_filter_valid': 1, 'name_filter': 'tap'}),
                         papi.sw_interface_dump('tap'))
        self.assertEqual((papi.papi.sw_interface_set_table,
                          {'sw_if_index': 1, 'is_ipv6': 0, 'vrf_id': 10}),
                         papi.sw_interface_set_table(1, 0, 10))
        self.assertEqual((papi.papi.sw_interface_add_del_address,
                          {'sw_if_index': 1, 'is_add': 1, 'is_ipv6': 0,
                           'del_all': 0, 'address_length': 24,
                           'address': b'addr'}),
                         papi.sw_interface_add_del_address(1, b'addr', 24))
        self.assertEqual((papi.papi.sw_interface_set_unnumbered,
                          {'sw_if_index': 2, 'unnumbered_sw_if_index': 1,
                           'is_add': 1}),
                         papi.sw_interface_set_unnumbered(1, 2))
        self.assertEqual((papi.papi.sw_interface_set_mpls_enable,
                          {'sw_if_index': 1, 'enable': 1}),
                         papi.sw_interface_enable_disable_mpls(1))
        self.assertEqual((papi.papi.sw_interface_ip6nd_ra_config,
                          {'sw_if_index': 1, 'suppress': 1}),
                         papi.sw_interface_ra_suppress(1))
        self.assertEqual((papi.papi.set_ip_flow_hash,
                          {'vrf_id': 1, 'src': 1, 'dst': 1, 'dport': 1,
                           'sport': 1, 'proto': 1, 'reverse': 0,
                           'is_ipv6': 0}),
                         papi.set_ip_flow_hash(1))
        self.assertEqual((papi.papi.ip6nd_proxy_add_del,
                          {'address': b'addr', 'sw_if_index': 1,
                           'is_del': 0}),
                         papi.ip6_nd_proxy(b'addr', 1))
        self.assertEqual((papi.papi.vxlan_add_del_tunnel,
                          {'is_add': 1, 'is_ipv6': 0,
                           'src_address': b'src', 'dst_address': b'dst',
                           'mcast_sw_if_index': 0xFFFFFFFF,
                           'encap_vrf_id': 0, 'decap_next_index': 0xFFFFFFFF,
                           'vni': 0}),
                         papi.vxlan_add_del_tunnel(b'src', b'dst'))
        self.assertEqual((papi.papi.create_vhost_user_if,
                          {'sock_filename': b'sock', 'is_server': 1,
                           'use_custom_mac': 1, 'mac_address': b'mac',
                           'tag': b'tag'}),
                         papi.create_vhostuser_socket(b'sock', 1, b'mac',
                                                      b'tag'))
        self.assertEqual((papi.papi.delete_vhost_user_if,
                          {'sw_if_index': 4}),
                         papi.delete_vhostuser_socket(4))
        self.assertEqual((papi.papi.sw_interface_set_flags,
                          {'sw_if_index': 4, 'admin_up_down': 1}),
                         papi.set_interface_state(4, 1))
        self.assertEqual((papi.papi.af_packet_create,
                          {'host_if_name': b'tap0', 'hw_addr': b'mac'}),
                         papi.af_packet_create(b'tap0', b'mac'))
        self.assertEqual((papi.papi.af_packet_delete,
                          {'host_if_name': b'tap0'}),
                         papi.af_packet_delete(b'tap0'))
        self.assertEqual((papi.papi.sw_interface_tag_add_del,
                          {'sw_if_index': 4, 'is_add': 1, 'tag': b'tag'}),
                         papi.set_interface_tag(4, b'tag'))
        self.assertEqual((papi.papi.sw_interface_set_mtu,
                          {'sw_if_index': 4, 'mtu': [1500, 0, 0, 0]}),
                         papi.set_interface_mtu(4, [1500, 0, 0, 0]))

    def test_vppapi_high_level_methods_use_context(self):
        provider, vppapi = self._load_vpplib()
        reply = collections.namedtuple('Reply', ['sw_if_index', 'retval'])(
            12, 0)
        vhost = collections.namedtuple(
            'Vhost', ['interface_name', 'sock_filename', 'sock_errno',
                      'num_regions', 'sw_if_index'])(
                          'VirtualEthernet0\0', '/tmp/sock\0', 0, 1, 12)
        interface = collections.namedtuple(
            'Interface', ['interface_name', 'l2_address', 'tag',
                          'sw_if_index'])(
                              'VirtualEthernet0\0',
                              b'\xaa\xbb\xcc\xdd\xee\xff', 'tag\0', 12)
        host_interface = collections.namedtuple(
            'HostInterface', ['interface_name', 'l2_address', 'tag',
                              'sw_if_index'])(
                                  'host-tap0\0',
                                  b'\xaa\xbb\xcc\xdd\xee\xff', 'host-tag\0',
                                  13)
        vppp = mock.Mock()
        vppp.show_version.return_value = reply
        vppp.create_vhostuser_socket.return_value = reply
        vppp.sw_interface_vhost_user_dump.return_value = [vhost]
        vppp.sw_interface_dump.return_value = [interface, host_interface]
        vppp.delete_vhostuser_socket.return_value = reply
        vppp.set_interface_state.return_value = reply
        vppp.af_packet_create.return_value = reply
        vppp.af_packet_delete.return_value = reply
        vppp.set_interface_tag.return_value = reply
        vppp.set_interface_mtu.return_value = reply

        ctxt = mock.Mock()
        ctxt.__enter__ = mock.Mock(return_value=vppp)
        ctxt.__exit__ = mock.Mock(return_value=False)
        with mock.patch.object(vppapi, 'VppCtxt', return_value=ctxt):
            api = vppapi.VPPApi(mock.Mock(), 'client')
            api._handle_reply = mock.Mock(return_value=json.dumps(
                {'sw_if_index': 12, 'retval': 0}))
            api._handle_vhost = mock.Mock(return_value=json.dumps([
                {'interface_name': 'VirtualEthernet0',
                 'sock_filename': '/tmp/sock', 'sock_errno': 0,
                 'num_regions': 1, 'sw_if_index': 12}]))
            api._handle_mac = mock.Mock(return_value=json.dumps([
                {'interface_name': 'VirtualEthernet0',
                 'l2_address': 'aa:bb:cc:dd:ee:ff', 'tag': 'tag',
                 'sw_if_index': 12},
                {'interface_name': 'host-tap0',
                 'l2_address': 'aa:bb:cc:dd:ee:ff', 'tag': 'host-tag',
                 'sw_if_index': 13}]))
            self.assertEqual({'sw_if_index': 12, 'retval': 0},
                             api.get_version())
            self.assertEqual((0, {'interface_name': 'VirtualEthernet0',
                                  'sock_filename': '/tmp/sock',
                                  'sock_errno': 0, 'num_regions': 1,
                                  'sw_if_index': 12}),
                             api.vhost_status('/tmp/sock'))
            self.assertEqual(12, api.create_vhost_user_if(
                b'/tmp/sock', 1, b'mac', b'tag'))
            self.assertEqual(set(['VirtualEthernet0']), api.show_vhost_user())
            self.assertEqual(set(['aa:bb:cc:dd:ee:ff']),
                             api.get_vhost_macs())
            self.assertEqual({'tag': '/tmp/sock', 'host-tag': 'tap0'},
                             api.get_vhost_tag_dicts())
            self.assertEqual('/tmp/sock', api.vhost_name_from_mac(
                'aa:bb:cc:dd:ee:ff'))
            self.assertEqual(('/tmp/sock', 'aa:bb:cc:dd:ee:ff', 12),
                             api.vhost_details_from_tag('tag'))
            api.delete_vhost_user_if('/tmp/sock')
            api.set_interface_state(12, 1)
            self.assertEqual(12, api.create_host_interface(
                b'tap0', b'mac', b'uuid'))
            api.delete_host_interface(b'tap0')
            api.set_interface_mtu(12, [1500, 0, 0, 0])
