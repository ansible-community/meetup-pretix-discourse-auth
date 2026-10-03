import base64
import hashlib
import hmac
import secrets
from urllib.parse import urlencode

from django.urls import reverse
from pretix.base.auth import BaseAuthBackend
from pretix.settings import config

DISCOURSE_URL = config.get('discourse_auth', 'url', fallback='')
DISCOURSE_SECRET = config.get('discourse_auth', 'sso_secret', fallback='')

class DiscourseAuthBackend(BaseAuthBackend):
    identifier = 'discourse'
    verbose_name = 'Log in with Discourse'

    @property
    def visible(self):
        return bool(DISCOURSE_URL and DISCOURSE_SECRET)

    def authentication_url(self, request):
        if not DISCOURSE_URL or not DISCOURSE_SECRET:
            return None

        # Generate a single-use random nonce
        nonce = secrets.token_urlsafe(32)
        request.session['discourse_sso_nonce'] = nonce

        return_url = request.build_absolute_uri(reverse('plugins:pretix_discourse_auth:return'))
        payload = f"nonce={nonce}&return_sso_url={return_url}"

        payload_b64 = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
        sig = hmac.new(
            DISCOURSE_SECRET.encode('utf-8'),
            payload_b64.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        query = urlencode({'sso': payload_b64, 'sig': sig})
        return f"{DISCOURSE_URL.rstrip('/')}/session/sso_provider?{query}"
