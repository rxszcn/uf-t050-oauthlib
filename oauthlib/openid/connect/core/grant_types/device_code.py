"""
oauthlib.openid.connect.core.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging

from oauthlib.oauth2.rfc8628.grant_types import (
    DeviceCodeGrant as OAuth2DeviceCodeGrant,
)

from .base import GrantTypeBase

log = logging.getLogger(__name__)


class DeviceCodeGrant(GrantTypeBase):

    def __init__(self, request_validator=None, **kwargs):
        self.proxy_target = OAuth2DeviceCodeGrant(
            request_validator=request_validator, **kwargs)
        self.register_token_modifier(self.add_id_token)

    def add_id_token(self, token, token_handler, request):
        """
        Construct an initial version of id_token, and let the
        request_validator sign or encrypt it.

        The device_code version of this method is used to
        retrieve the nonce accordingly to the device code storage.
        """
        # Treat it as normal OAuth 2 device code request if openid is not present
        if not request.scopes or 'openid' not in request.scopes:
            return token

        nonce = self.request_validator.get_device_code_nonce(
            request.client_id,
            request.device_code,
            request
        )
        return super().add_id_token(token, token_handler, request, nonce=nonce)
