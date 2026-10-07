import base64
import hashlib
import hmac
import logging
import secrets
import time
from urllib.parse import urlencode, urlparse

from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from pretix.base.auth import BaseAuthBackend
from pretix.settings import config

logger = logging.getLogger(__name__)

DISCOURSE_URL = config.get('discourse_auth', 'url', fallback='')
DISCOURSE_SECRET = config.get('discourse_auth', 'sso_secret', fallback='')
API_KEY = config.get('discourse_auth', 'api_key', fallback='')
ALLOW_HTTP = config.get('discourse_auth', 'allow_http', fallback='false').lower() == 'true'

_config_errors = []

if DISCOURSE_URL:
    try:
        parsed_discourse_url = urlparse(DISCOURSE_URL)
        # Reading .port also rejects malformed ports in the configured URL.
        discourse_port = parsed_discourse_url.port
        local_discourse_host = parsed_discourse_url.hostname in {'localhost', '127.0.0.1', '::1'}
        valid_discourse_url = bool(
            parsed_discourse_url.hostname
            and parsed_discourse_url.username is None
            and parsed_discourse_url.password is None
            and not parsed_discourse_url.query
            and not parsed_discourse_url.fragment
            and (discourse_port is None or 1 <= discourse_port <= 65535)
            and (
                parsed_discourse_url.scheme == 'https'
                or (ALLOW_HTTP and parsed_discourse_url.scheme == 'http' and local_discourse_host)
            )
        )
    except ValueError:
        valid_discourse_url = False
    if not valid_discourse_url:
        _config_errors.append(
            "discourse_auth.url must use HTTPS (HTTP is allowed only for localhost/loopback development)"
        )
        logger.error(
            "discourse_auth.url must use HTTPS — HTTP is allowed only for localhost/loopback development"
        )

if DISCOURSE_SECRET and len(DISCOURSE_SECRET) < 32:
    _config_errors.append("discourse_auth.sso_secret must be at least 32 characters")
    logger.error("discourse_auth.sso_secret is too short (minimum 32 characters)")

if DISCOURSE_URL and DISCOURSE_SECRET and not API_KEY:
    _config_errors.append("discourse_auth.api_key is required for security enrichment")
    logger.error("discourse_auth.api_key is required — backend will not be visible")

class DiscourseAuthBackend(BaseAuthBackend):
    identifier = 'discourse'
    verbose_name = _('Log in with Discourse')

    @property
    def visible(self):
        return bool(DISCOURSE_URL and DISCOURSE_SECRET and API_KEY and not _config_errors)

    def authentication_url(self, request):
        if not self.visible:
            return None

        nonce = secrets.token_urlsafe(32)
        request.session['discourse_sso_nonce'] = nonce
        request.session['discourse_sso_nonce_created'] = time.time()

        return_url = request.build_absolute_uri(reverse('plugins:pretix_discourse_auth:return'))
        # This is a fixed security policy: DiscourseConnect challenges for 2FA
        # during authentication. A successful signed callback is the assertion.
        payload = f"nonce={nonce}&return_sso_url={return_url}&require_2fa=true"

        payload_b64 = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
        sig = hmac.new(
            DISCOURSE_SECRET.encode('utf-8'),
            payload_b64.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        query = urlencode({'sso': payload_b64, 'sig': sig})
        return f"{DISCOURSE_URL.rstrip('/')}/session/sso_provider?{query}"
