# -*- encoding: utf-8 -*-
#
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

"""Tests for the Pecan API hooks."""

from http import client as http_client
import json
from unittest import mock

from oslo_config import cfg
import oslo_messaging as messaging
import webtest

from ironic.api.controllers import base as api_base
from ironic.api.controllers import root
from ironic.api.controllers import v1 as api_v1
from ironic.api.controllers.v1 import utils as api_utils
from ironic.api import hooks
from ironic.common import context
from ironic.common import exception
from ironic.common import policy
from ironic.tests import base as tests_base
from ironic.tests.unit.api import base
from ironic.tests.unit.objects import utils as obj_utils


class FakeRequest(object):
    def __init__(self, headers, context, environ):
        self.headers = headers
        self.context = context
        self.environ = environ or {}
        self.version = (1, 0)
        self.host_url = 'http://127.0.0.1:6385'


class FakeRequestState(object):
    def __init__(self, headers=None, context=None, environ=None):
        self.request = FakeRequest(headers, context, environ)
        self.response = FakeRequest(headers, context, environ)


def fake_headers(admin=False):
    headers = {
        'X-Auth-Token': '8d9f235ca7464dd7ba46f81515797ea0',
        'X-Domain-Id': 'None',
        'X-Domain-Name': 'None',
        'X-Project-Domain-Id': 'default',
        'X-Project-Domain-Name': 'Default',
        'X-Project-Id': 'b4efa69d4ffa4973863f2eefc094f7f8',
        'X-Project-Name': 'admin',
        'X-Role': '_member_,admin',
        'X-Roles': '_member_,admin',
        'X-Tenant': 'foo',
        'X-Tenant-Id': 'b4efa69d4ffa4973863f2eefc094f7f8',
        'X-Tenant-Name': 'foo',
        'X-User': 'foo',
        'X-User-Domain-Id': 'default',
        'X-User-Domain-Name': 'Default',
        'X-User-Id': '604ab2a197c442c2a84aba66708a9e1e',
        'X-User-Name': 'foo',
        'X-OpenStack-Ironic-API-Version': '1.0'
    }
    if admin:
        headers.update({
            'X-Project-Name': 'admin',
            'X-Role': '_member_,admin',
            'X-Roles': '_member_,admin',
            'X-Tenant': 'admin',
            'X-Tenant-Name': 'admin',
        })
    else:
        headers.update({
            'X-Project-Name': 'foo',
            'X-Role': '_member_',
            'X-Roles': '_member_',
        })
    return headers


def headers_to_environ(headers, **kwargs):
    environ = {}
    for k, v in headers.items():
        environ['HTTP_%s' % k.replace('-', '_').upper()] = v
    environ.update(kwargs)
    return environ


class TestNoExceptionTracebackHook(base.BaseApiTest):

    TRACE = [u'Traceback (most recent call last):',
             u'  File "/opt/stack/ironic/ironic/common/rpc/amqp.py",'
             ' line 434, in _process_data\\n   **args)',
             u'  File "/opt/stack/ironic/ironic/common/rpc/'
             'dispatcher.py", line 172, in dispatch\\n   result ='
             ' getattr(proxyobj, method)(ctxt, **kwargs)']
    MSG_WITHOUT_TRACE = "Test exception message."
    MSG_WITH_TRACE = MSG_WITHOUT_TRACE + "\n" + "\n".join(TRACE)

    def setUp(self):
        super(TestNoExceptionTracebackHook, self).setUp()
        p = mock.patch.object(root, 'root', autospec=True)
        self.root_convert_mock = p.start()
        self.addCleanup(p.stop)

    def test_hook_exception_success(self):
        self.root_convert_mock.side_effect = Exception(self.MSG_WITH_TRACE)

        response = self.get_json('/', path_prefix='', expect_errors=True)

        actual_msg = json.loads(response.json['error_message'])['faultstring']
        self.assertEqual(self.MSG_WITHOUT_TRACE, actual_msg)

    def test_hook_remote_error_success(self):
        test_exc_type = 'TestException'
        self.root_convert_mock.side_effect = messaging.rpc.RemoteError(
            test_exc_type, self.MSG_WITHOUT_TRACE, self.TRACE)

        response = self.get_json('/', path_prefix='', expect_errors=True)

        # NOTE(max_lobur): For RemoteError the client message will still have
        # some garbage because in RemoteError traceback is serialized as a list
        # instead of'\n'.join(trace). But since RemoteError is kind of very
        # rare thing (happens due to wrong deserialization settings etc.)
        # we don't care about this garbage.
        expected_msg = ("Remote error: %s %s"
                        % (test_exc_type, self.MSG_WITHOUT_TRACE)
                        + "\n['")
        actual_msg = json.loads(response.json['error_message'])['faultstring']
        self.assertEqual(expected_msg, actual_msg)

    def _test_hook_without_traceback(self):
        msg = "Error message without traceback \n but \n multiline"
        self.root_convert_mock.side_effect = Exception(msg)

        response = self.get_json('/', path_prefix='', expect_errors=True)

        actual_msg = json.loads(response.json['error_message'])['faultstring']
        self.assertEqual(msg, actual_msg)

    def test_hook_without_traceback(self):
        self._test_hook_without_traceback()

    def test_hook_without_traceback_debug(self):
        cfg.CONF.set_override('debug', True)
        self._test_hook_without_traceback()

    def test_hook_without_traceback_debug_tracebacks(self):
        cfg.CONF.set_override('debug_tracebacks_in_api', True)
        self._test_hook_without_traceback()

    def _test_hook_on_serverfault(self):
        self.root_convert_mock.side_effect = Exception(self.MSG_WITH_TRACE)

        response = self.get_json('/', path_prefix='', expect_errors=True)

        actual_msg = json.loads(
            response.json['error_message'])['faultstring']
        return actual_msg

    def test_hook_on_serverfault(self):
        msg = self._test_hook_on_serverfault()
        self.assertEqual(self.MSG_WITHOUT_TRACE, msg)

    def test_hook_on_serverfault_debug(self):
        cfg.CONF.set_override('debug', True)
        msg = self._test_hook_on_serverfault()
        self.assertEqual(self.MSG_WITHOUT_TRACE, msg)

    def test_hook_on_serverfault_debug_tracebacks(self):
        cfg.CONF.set_override('debug_tracebacks_in_api', True)
        msg = self._test_hook_on_serverfault()
        self.assertEqual(self.MSG_WITH_TRACE, msg)

    def _test_hook_on_clientfault(self):
        client_error = Exception(self.MSG_WITH_TRACE)
        client_error.code = http_client.BAD_REQUEST
        self.root_convert_mock.side_effect = client_error

        response = self.get_json('/', path_prefix='', expect_errors=True)

        actual_msg = json.loads(
            response.json['error_message'])['faultstring']
        return actual_msg

    def test_hook_on_clientfault(self):
        msg = self._test_hook_on_clientfault()
        self.assertEqual(self.MSG_WITHOUT_TRACE, msg)

    def test_hook_on_clientfault_debug(self):
        cfg.CONF.set_override('debug', True)
        msg = self._test_hook_on_clientfault()
        self.assertEqual(self.MSG_WITHOUT_TRACE, msg)

    def test_hook_on_clientfault_debug_tracebacks(self):
        cfg.CONF.set_override('debug_tracebacks_in_api', True)
        msg = self._test_hook_on_clientfault()
        self.assertEqual(self.MSG_WITH_TRACE, msg)


class TestContextHook(base.BaseApiTest):

    @mock.patch.object(context, 'RequestContext', autospec=True)
    @mock.patch.object(policy, 'check', autospec=True)
    def _test_context_hook(self, mock_policy, mock_ctx, is_admin=False,
                           is_public_api=False, auth_strategy='keystone',
                           request_id=None, auth_token_info=None):
        cfg.CONF.set_override('auth_strategy', auth_strategy)
        headers = fake_headers(admin=is_admin)
        environ = headers_to_environ(
            headers,
            **{'is_public_api': is_public_api,
               'keystone.token_info': auth_token_info})
        reqstate = FakeRequestState(headers=headers, environ=environ)
        context_hook = hooks.ContextHook(None)
        ctx = mock.Mock()
        if request_id:
            ctx.request_id = request_id
        mock_ctx.from_environ.return_value = ctx
        policy_dict = {'user_id': 'foo'}  # Lots of other values here
        ctx.to_policy_values.return_value = policy_dict
        mock_policy.return_value = False
        context_hook.before(reqstate)
        creds_dict = {'is_public_api': is_public_api}
        if auth_token_info:
            creds_dict['auth_token_info'] = auth_token_info
            mock_ctx.from_environ.assert_called_once_with(
                environ, **creds_dict)
        mock_policy.assert_not_called()
        if auth_strategy == 'noauth':
            self.assertIsNone(ctx.auth_token)
        mock_policy.assert_not_called()
        return context_hook, reqstate

    def test_context_hook_not_admin(self):
        self._test_context_hook()

    def test_context_hook_public_api(self):
        self._test_context_hook(is_public_api=True)

    def test_context_hook_noauth_token_removed(self):
        self._test_context_hook(auth_strategy='noauth')

    def test_context_hook_after_add_request_id(self):
        context_hook, reqstate = self._test_context_hook(request_id='fake-id')
        context_hook.after(reqstate)
        self.assertEqual('fake-id',
                         reqstate.response.headers['Openstack-Request-Id'])

    def test_context_hook_after_miss_context(self):
        response = self.get_json('/bad/path',
                                 expect_errors=True)
        self.assertNotIn('Openstack-Request-Id',
                         response.headers)

    def test_context_hook_auth_token_info(self):
        self._test_context_hook(auth_token_info='data-dict')


class TestPolicyDeprecation(tests_base.TestCase):

    @mock.patch.object(hooks, 'CHECKED_DEPRECATED_POLICY_ARGS', False)
    @mock.patch.object(hooks.LOG, 'warning', autospec=True)
    @mock.patch.object(policy, 'get_enforcer', autospec=True)
    def test_policy_deprecation_check(self, enforcer_mock, warning_mock):
        rules = {'is_member': 'project_name:demo or tenant:baremetal',
                 'is_default_project_domain': 'project_domain_id:default'}
        enforcer_mock.return_value = mock.Mock(file_rules=rules, autospec=True)
        hooks.policy_deprecation_check()
        self.assertEqual(1, warning_mock.call_count)


class TestPublicUrlHook(base.BaseApiTest):

    def test_before_host_url(self):
        headers = fake_headers()
        reqstate = FakeRequestState(headers=headers)
        trusted_call_hook = hooks.PublicUrlHook()
        trusted_call_hook.before(reqstate)
        self.assertEqual(reqstate.request.host_url,
                         reqstate.request.public_url)

    def test_before_public_endpoint(self):
        cfg.CONF.set_override('public_endpoint', 'http://foo', 'api')
        headers = fake_headers()
        reqstate = FakeRequestState(headers=headers)
        trusted_call_hook = hooks.PublicUrlHook()
        trusted_call_hook.before(reqstate)
        self.assertEqual('http://foo', reqstate.request.public_url)


class TestAuditNodeIdentsHook(base.BaseApiTest):
    """[ccloud] node name lookups as seen by the audit middleware."""

    def setUp(self):
        super(TestAuditNodeIdentsHook, self).setUp()
        self.node = obj_utils.create_test_node(
            self.context, name='node-1',
            owner='97879042-c0bf-4216-882a-66a7cbf2bd74')
        self.headers = {
            api_base.Version.string: str(api_v1.max_version())}

    def _idents_after(self, method, path, headers, **kwargs):
        # look at the WSGI environ after the app returned, like the audit
        # middleware wrapping the API does
        captured = {}
        inner = self.app.app

        def wrapper(environ, start_response):
            try:
                return inner(environ, start_response)
            finally:
                captured.update(environ)

        resp = getattr(webtest.TestApp(wrapper), method)(
            '/v1' + path, headers=headers, expect_errors=True, **kwargs)
        return resp.status_int, captured.get(
            api_utils.NODE_IDENTS_ENVIRON_KEY)

    def test_visible_node_by_name(self):
        status, idents = self._idents_after('get', '/nodes/node-1',
                                            self.headers)
        self.assertEqual(http_client.OK, status)
        self.assertEqual({'node-1': self.node.uuid}, idents)

    def test_node_by_uuid(self):
        status, idents = self._idents_after(
            'get', '/nodes/%s' % self.node.uuid, self.headers)
        self.assertEqual(http_client.OK, status)
        self.assertIsNone(idents)

    @mock.patch.object(policy, 'authorize', spec=True)
    def _test_concealed(self, method, path, mock_authorize, **kwargs):
        def authorize(rule, target, creds):
            if rule in ('baremetal:node:get',
                        'baremetal:node:get_allocation',
                        'baremetal:allocation:delete'):
                raise exception.HTTPForbidden(resource='fake')
            return True
        mock_authorize.side_effect = authorize
        headers = dict(self.headers)
        headers['X-Project-ID'] = '46c0bf8a-846d-49a5-9724-5a61a5efa6bf'
        status, idents = self._idents_after(method, path, headers, **kwargs)
        self.assertEqual(http_client.NOT_FOUND, status)
        self.assertIsNone(idents)

    def test_concealed_node_by_name(self):
        self._test_concealed('get', '/nodes/node-1')

    def test_concealed_node_states_by_name(self):
        self._test_concealed('put_json', '/nodes/node-1/states/power',
                             params={'target': 'power on'})

    def test_concealed_node_allocation_by_name(self):
        self._test_concealed('get', '/nodes/node-1/allocation')
        self._test_concealed('delete', '/nodes/node-1/allocation')

    @mock.patch.object(policy, 'authorize', spec=True)
    def test_denied_action_on_visible_node_keeps_ident(self, mock_authorize):
        def authorize(rule, target, creds):
            if rule == 'baremetal:node:set_power_state':
                raise exception.HTTPForbidden(resource='fake')
            return True
        mock_authorize.side_effect = authorize
        status, idents = self._idents_after(
            'put_json', '/nodes/node-1/states/power', self.headers,
            params={'target': 'power on'})
        self.assertEqual(http_client.FORBIDDEN, status)
        self.assertEqual({'node-1': self.node.uuid}, idents)
