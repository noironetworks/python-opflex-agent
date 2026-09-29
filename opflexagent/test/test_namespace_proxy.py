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
import os
import tempfile

from unittest import mock

from neutron.tests import base
import webob

from opflexagent import namespace_proxy


class _HttpResponse(dict):
    def __init__(self, status, **kwargs):
        super(_HttpResponse, self).__init__(**kwargs)
        self.status = status


class TestNamespaceProxy(base.BaseTestCase):

    def test_handler_requires_identifier(self):
        self.assertRaises(ValueError,
                  namespace_proxy.NetworkMetadataProxyHandler)

    def test_get_network_id_from_state_file(self):
        data = {'domain-1': {'10.0.0.2': 'network-1'}}
        with mock.patch('builtins.open', mock.mock_open(
                read_data=json.dumps(data))):
            handler = namespace_proxy.NetworkMetadataProxyHandler(
                domain_id='domain-1')
            self.assertEqual(
                'network-1', handler.get_network_id('domain-1', '10.0.0.2'))
            self.assertIsNone(
                handler.get_network_id('domain-1', '10.0.0.3'))

    def test_get_network_id_returns_none_on_read_error(self):
        with mock.patch('builtins.open', side_effect=IOError('boom')):
            handler = namespace_proxy.NetworkMetadataProxyHandler(
                domain_id='domain-1')
            self.assertIsNone(
                handler.get_network_id('domain-1', '10.0.0.2'))

    def test_proxy_request_sets_network_header_and_returns_response(self):
        response = _HttpResponse(200, **{'content-type': 'text/plain'})
        http = mock.Mock()
        http.request.return_value = response, b'body'
        with mock.patch('httplib2.Http', return_value=http):
            handler = namespace_proxy.NetworkMetadataProxyHandler(
                network_id='network-1')
            result = handler._proxy_request(
                '10.0.0.2', 'GET', '/meta', 'a=b', b'')

        self.assertEqual(200, result.status_int)
        self.assertEqual(b'body', result.body)
        http.request.assert_called_once_with(
            'http://169.254.169.254/meta?a=b', method='GET',
            headers={'X-Forwarded-For': '10.0.0.2',
                     'X-Neutron-Network-ID': 'network-1'},
            body=b'',
            connection_type=(
                namespace_proxy.agent_utils.UnixDomainHTTPConnection))

    def test_proxy_request_maps_metadata_status_codes(self):
        handler = namespace_proxy.NetworkMetadataProxyHandler(
            router_id='router')
        for status, exc_cls in [(400, webob.exc.HTTPBadRequest),
                                (404, webob.exc.HTTPNotFound),
                                (409, webob.exc.HTTPConflict),
                                (500, webob.exc.HTTPInternalServerError)]:
            http = mock.Mock()
            http.request.return_value = _HttpResponse(status), b''
            with mock.patch('httplib2.Http', return_value=http):
                self.assertIsInstance(
                    handler._proxy_request('10.0.0.2', 'GET', '/', '', b''),
                    exc_cls)

    def test_proxy_request_returns_not_found_without_domain_mapping(self):
        handler = namespace_proxy.NetworkMetadataProxyHandler(
            domain_id='domain-1')
        with mock.patch.object(handler, 'get_network_id', return_value=None):
            self.assertIsInstance(
                handler._proxy_request('10.0.0.2', 'GET', '/', '', b''),
                webob.exc.HTTPNotFound)

    def test_proxy_request_raises_unexpected_status(self):
        http = mock.Mock()
        http.request.return_value = _HttpResponse(418), b''
        with mock.patch('httplib2.Http', return_value=http):
            handler = namespace_proxy.NetworkMetadataProxyHandler(
                network_id='network-1')
            with self.assertRaisesRegex(
                    Exception, 'Unexpected response code: 418'):
                handler._proxy_request('10.0.0.2', 'GET', '/', '', b'')

    def test_call_returns_internal_server_error_on_exception(self):
        handler = namespace_proxy.NetworkMetadataProxyHandler(
            network_id='network-1')
        with mock.patch.object(handler, '_proxy_request',
                               side_effect=Exception('boom')):
            request = webob.Request.blank('/')
            request.remote_addr = '10.0.0.2'
            response = handler(request)
        self.assertEqual(500, response.status_int)

    def test_proxy_daemon_run_starts_server_and_waits(self):
        pidfile = tempfile.NamedTemporaryFile().name
        self.addCleanup(lambda: os.path.exists(pidfile) and os.remove(pidfile))
        with mock.patch('setproctitle.getproctitle', return_value='parent'), \
                mock.patch('opflexagent.namespace_proxy.wsgi.Server',
                           create=True) as server:
            proxy = server.return_value
            daemon = namespace_proxy.ProxyDaemon(
                pidfile, 9697, network_id='network-1')
            with mock.patch.object(namespace_proxy.daemon.Daemon, 'run'):
                daemon.run()
        proxy.start.assert_called_once_with(mock.ANY, 9697, host='0.0.0.0')
        proxy.wait.assert_called_once_with()
