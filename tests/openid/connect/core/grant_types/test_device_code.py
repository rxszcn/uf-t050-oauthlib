import json
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc8628.grant_types import (
    DeviceCodeGrant as OAuth2DeviceCodeGrant,
)
from oauthlib.openid.connect.core.grant_types import DeviceCodeGrant

from tests.unittest import TestCase


def get_id_token_mock(token, token_handler, request):
    return "MOCKED_TOKEN"

DEVICE_CODE_AUTHORIZED = OAuth2DeviceCodeGrant.DEVICE_CODE_AUTHORIZED
DEVICE_CODE_PENDING = OAuth2DeviceCodeGrant.DEVICE_CODE_PENDING


class OpenIDDeviceCodeInterferenceTest(TestCase):
    """Test that OpenID don't interfere with normal OAuth 2 device flows."""

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
        self.request.device_code = 'device_code_1234'
        self.request.client_id = 'abcdef'
        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = self.set_client
        self.mock_validator.validate_device_code.side_effect = self.authorize
        self.auth = DeviceCodeGrant(request_validator=self.mock_validator)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'abcdef'
        return True

    def authorize(self, client_id, device_code, request):
        request.scopes = ['hello', 'world']
        request.user = mock.MagicMock()
        return DEVICE_CODE_AUTHORIZED

    def test_no_id_token_without_openid_scope(self):
        bearer = BearerToken(self.mock_validator)

        _headers, body, status_code = self.auth.create_token_response(
            self.request, bearer
        )

        token = json.loads(body)
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertIn('token_type', token)
        self.assertIn('expires_in', token)
        self.assertEqual(token['scope'], 'hello world')
        self.assertNotIn('id_token', token)
        self.assertEqual(self.mock_validator.save_token.call_count, 1)
        self.mock_validator.get_device_code_nonce.assert_not_called()
        self.mock_validator.get_id_token.assert_not_called()
        self.mock_validator.finalize_id_token.assert_not_called()

    def test_authorization_pending_still_raises(self):
        self.mock_validator.validate_device_code.side_effect = None
        self.mock_validator.validate_device_code.return_value = (
            DEVICE_CODE_PENDING
        )
        bearer = BearerToken(self.mock_validator)

        _headers, body, status_code = self.auth.create_token_response(
            self.request, bearer
        )

        self.assertEqual(json.loads(body), {'error': 'authorization_pending'})
        self.assertEqual(status_code, 400)
        self.mock_validator.save_token.assert_not_called()


class OpenIDDeviceCodeTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
        self.request.device_code = 'device_code_1234'
        self.request.client_id = 'abcdef'
        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = self.set_client
        self.mock_validator.validate_device_code.side_effect = self.authorize
        self.mock_validator.get_id_token.side_effect = get_id_token_mock
        self.mock_validator.get_device_code_nonce.return_value = 'nonce-xyz'
        self.auth = DeviceCodeGrant(request_validator=self.mock_validator)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'abcdef'
        return True

    def authorize(self, client_id, device_code, request):
        request.scopes = ['hello', 'openid']
        request.user = mock.MagicMock()
        return DEVICE_CODE_AUTHORIZED

    def test_device_flow_issues_id_token(self):
        bearer = BearerToken(self.mock_validator)

        _headers, body, status_code = self.auth.create_token_response(
            self.request, bearer
        )

        token = json.loads(body)
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertIn('token_type', token)
        self.assertIn('expires_in', token)
        self.assertEqual(token['scope'], 'hello openid')
        self.assertEqual(token['id_token'], 'MOCKED_TOKEN')
        self.assertEqual(self.mock_validator.save_token.call_count, 1)
        self.mock_validator.get_device_code_nonce.assert_called_once_with(
            'abcdef', 'device_code_1234', self.request
        )

    def test_device_flow_nonce_reaches_finalize_id_token(self):
        self.mock_validator.get_id_token.side_effect = None
        self.mock_validator.get_id_token.return_value = None
        self.mock_validator.finalize_id_token.return_value = 'SIGNED_ID_TOKEN'
        bearer = BearerToken(self.mock_validator)

        _headers, body, _status_code = self.auth.create_token_response(
            self.request, bearer
        )

        token = json.loads(body)
        self.assertEqual(token['id_token'], 'SIGNED_ID_TOKEN')
        id_token = self.mock_validator.finalize_id_token.call_args[0][0]
        self.assertEqual(id_token['nonce'], 'nonce-xyz')
        self.assertEqual(id_token['aud'], 'abcdef')
        self.assertIn('iat', id_token)
        self.assertIn('at_hash', id_token)

    def test_device_flow_without_nonce(self):
        self.mock_validator.get_device_code_nonce.return_value = None
        self.mock_validator.get_id_token.side_effect = None
        self.mock_validator.get_id_token.return_value = None
        self.mock_validator.finalize_id_token.return_value = 'SIGNED_ID_TOKEN'
        bearer = BearerToken(self.mock_validator)

        self.auth.create_token_response(self.request, bearer)

        id_token = self.mock_validator.finalize_id_token.call_args[0][0]
        self.assertNotIn('nonce', id_token)
