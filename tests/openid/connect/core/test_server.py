# -*- coding: utf-8 -*-
import json
from unittest import mock

from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.endpoints.authorization import (
    AuthorizationEndpoint,
)
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc8628.grant_types import (
    DeviceCodeGrant as OAuth2DeviceCodeGrant,
)
from oauthlib.openid.connect.core.endpoints.pre_configured import Server
from oauthlib.openid.connect.core.grant_types.authorization_code import (
    AuthorizationCodeGrant,
)
from oauthlib.openid.connect.core.grant_types.hybrid import HybridGrant
from oauthlib.openid.connect.core.grant_types.implicit import ImplicitGrant

from tests.unittest import TestCase


class AuthorizationEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.mock_validator.get_code_challenge.return_value = None
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = AuthorizationCodeGrant(request_validator=self.mock_validator)
        auth_code.save_authorization_code = mock.MagicMock()
        implicit = ImplicitGrant(
            request_validator=self.mock_validator)
        implicit.save_token = mock.MagicMock()
        hybrid = HybridGrant(self.mock_validator)

        response_types = {
            'code': auth_code,
            'token': implicit,
            'id_token': implicit,
            'id_token token': implicit,
            'code token': hybrid,
            'code id_token': hybrid,
            'code token id_token': hybrid,
            'none': auth_code
        }
        self.expires_in = 1800
        token = BearerToken(
            self.mock_validator,
            expires_in=self.expires_in
        )
        self.endpoint = AuthorizationEndpoint(
            default_response_type='code',
            default_token_type=token,
            response_types=response_types
        )

    # TODO: Add hybrid grant test

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        uri = 'http://i.b/l?response_type=code&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?code=abc&state=xyz')

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_implicit_grant(self):
        uri = 'http://i.b/l?response_type=token&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me#access_token=abc&expires_in=' + str(self.expires_in) + '&token_type=Bearer&state=xyz&scope=all+of+them', parse_fragment=True)

    def test_none_grant(self):
        uri = 'http://i.b/l?response_type=none&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, body, status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?state=xyz', parse_fragment=True)
        self.assertIsNone(body)
        self.assertEqual(status_code, 302)

        # and without the state parameter
        uri = 'http://i.b/l?response_type=none&client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, body, status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me', parse_fragment=True)
        self.assertIsNone(body)
        self.assertEqual(status_code, 302)

    def test_missing_type(self):
        uri = 'http://i.b/l?client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
            side_effect=errors.InvalidRequestError())
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?error=invalid_request&error_description=Missing+response_type+parameter.')

    def test_invalid_type(self):
        uri = 'http://i.b/l?response_type=invalid&client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
            side_effect=errors.UnsupportedResponseTypeError())
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?error=unsupported_response_type')

    def test_reordered_response_type_uses_registered_handler(self):
        # RFC 6749 section 3.1.1: the order of response_type values does not matter.
        for response_type in ('id_token+code', 'id_token+token+code', 'token+id_token'):
            uri = 'http://i.b/l?response_type=%s&client_id=me&scope=openid' % response_type
            uri += '&state=xyz&nonce=n&redirect_uri=http%3A%2F%2Fback.to%2Fme'
            expected = {
                'id_token+code': ('code id_token', HybridGrant),
                'id_token+token+code': ('code token id_token', HybridGrant),
                'token+id_token': ('id_token token', ImplicitGrant),
            }[response_type]
            with mock.patch.object(expected[1], 'validate_authorization_request',
                                   autospec=True, return_value=([], {})) as validate:
                self.endpoint.validate_authorization_request(uri)
            request = validate.call_args[0][1]
            self.assertEqual(request.response_type, expected[0])

    def test_reordered_hybrid_response_type_requires_nonce(self):
        uri = 'http://i.b/l?response_type=id_token+code&client_id=me&scope=openid'
        uri += '&state=xyz&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['openid'])
        self.assertIn('Location', headers)
        self.assertIn('error=invalid_request', headers['Location'])
        self.assertIn('nonce', headers['Location'])

    def test_response_type_with_repeated_or_empty_values_is_not_rewritten(self):
        for response_type in ('code code', 'code  id_token', 'id_token code code', 'code bogus'):
            request = mock.MagicMock(response_type=response_type)
            self.endpoint._canonicalize_response_type(request)
            self.assertEqual(request.response_type, response_type)


class TokenEndpointTest(TestCase):

    def setUp(self):
        def set_user(request):
            request.user = mock.MagicMock()
            request.client = mock.MagicMock()
            request.client.client_id = 'mocked_client_id'
            return True

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = set_user
        self.mock_validator.get_code_challenge.return_value = None
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = AuthorizationCodeGrant(
            request_validator=self.mock_validator)
        supported_types = {
            'authorization_code': auth_code,
        }
        self.expires_in = 1800
        token = BearerToken(
            self.mock_validator,
            expires_in=self.expires_in
        )
        self.endpoint = TokenEndpoint(
            'authorization_code',
            default_token_type=token,
            grant_types=supported_types
        )

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        body = 'grant_type=authorization_code&code=abc&scope=all+of+them'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'refresh_token': 'abc',
            'scope': 'all of them'
        }
        self.assertEqual(json.loads(body), token)

        body = 'grant_type=authorization_code&code=abc'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'refresh_token': 'abc'
        }
        self.assertEqual(json.loads(body), token)

        # ignore useless fields
        body = 'grant_type=authorization_code&code=abc&state=foobar'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        self.assertEqual(json.loads(body), token)

    def test_missing_type(self):
        _, body, _ = self.endpoint.create_token_response('', body='')
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)

    def test_invalid_type(self):
        body = 'grant_type=invalid'
        _, body, _ = self.endpoint.create_token_response('', body=body)
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)


class DeviceCodeServerTest(TestCase):
    """End-to-end device flow through the all-in-one OpenID Connect Server."""

    def setUp(self):
        def set_client(request):
            request.client = mock.MagicMock()
            request.client.client_id = 'mocked_client_id'
            return True

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = set_client
        self.mock_validator.get_id_token.return_value = 'MOCKED_ID_TOKEN'
        self.mock_validator.get_device_code_nonce.return_value = 'nonce-xyz'
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        self.server = Server(self.mock_validator)

    def poll_token(self, scopes):
        def authorize(client_id, device_code, request):
            request.scopes = scopes
            request.user = mock.MagicMock()
            return OAuth2DeviceCodeGrant.DEVICE_CODE_AUTHORIZED

        self.mock_validator.validate_device_code.side_effect = authorize
        body = ('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code'
                '&device_code=device_code_1234&client_id=mocked_client_id')
        _headers, body, status_code = self.server.create_token_response(
            'https://i.b/token',
            body=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        return status_code, json.loads(body)

    def test_device_flow_issues_id_token_with_openid_scope(self):
        status_code, token = self.poll_token(['profile', 'openid'])

        self.assertEqual(status_code, 200)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertEqual(token['id_token'], 'MOCKED_ID_TOKEN')
        self.assertEqual(token['scope'], 'profile openid')
        self.assertEqual(self.mock_validator.save_token.call_count, 1)
        self.mock_validator.get_device_code_nonce.assert_called_once()

    def test_device_flow_without_openid_scope_omits_id_token(self):
        status_code, token = self.poll_token(['profile'])

        self.assertEqual(status_code, 200)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertNotIn('id_token', token)
        self.assertEqual(token['scope'], 'profile')
        self.assertEqual(self.mock_validator.save_token.call_count, 1)
        self.mock_validator.get_device_code_nonce.assert_not_called()
        self.mock_validator.get_id_token.assert_not_called()

    def test_device_flow_authorization_pending(self):
        self.mock_validator.validate_device_code.side_effect = None
        self.mock_validator.validate_device_code.return_value = (
            OAuth2DeviceCodeGrant.DEVICE_CODE_PENDING
        )
        body = ('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code'
                '&device_code=device_code_1234&client_id=mocked_client_id')
        _headers, body, status_code = self.server.create_token_response(
            'https://i.b/token',
            body=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )

        self.assertEqual(status_code, 400)
        self.assertEqual(json.loads(body), {'error': 'authorization_pending'})
        self.mock_validator.save_token.assert_not_called()
