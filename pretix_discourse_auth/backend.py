import base64
import hashlib
import hmac
import logging
import re
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from pretix.base.auth import BaseAuthBackend
from pretix.settings import config

logger = logging.getLogger(__name__)

ORGANIZERS_GROUP_RE = re.compile(r"^meetup-organisers-([a-z]+)$")
ORGANISERS_GROUP_PREFIX = "meetup-organisers-"
TEAM_NAME_PREFIX = "Ansible Meetup Organisers - "
RTBF_EMAIL_SUFFIX = "@anonymized.invalid"
NONCE_MAX_AGE_SECONDS = 600


@dataclass(frozen=True, slots=True)
class PluginSettings:
    """One validated snapshot of the plugin's Pretix configuration."""

    discourse_url: str
    discourse_secret: str
    api_key: str
    api_username: str
    organizer_slug: str
    api_timeout: int
    errors: tuple[str, ...]
    organizer_error: str | None

    @classmethod
    def load(cls) -> "PluginSettings":
        url = config.get("discourse_auth", "url", fallback="").strip()
        secret = config.get("discourse_auth", "sso_secret", fallback="")
        api_key = config.get("discourse_auth", "api_key", fallback="")
        api_username = config.get("discourse_auth", "api_username", fallback="system").strip()
        organizer_slug = config.get("discourse_auth", "organizer", fallback="").strip()
        errors: list[str] = []

        try:
            api_timeout = int(config.get("discourse_auth", "api_timeout", fallback="10"))
            if not 1 <= api_timeout <= 60:
                raise ValueError
        except ValueError:
            api_timeout = 10
            errors.append("discourse_auth.api_timeout must be an integer from 1 to 60")

        if not url:
            errors.append("discourse_auth.url is required")
        else:
            try:
                parsed = urlparse(url)
                port = parsed.port
                local_host = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                valid_url = bool(
                    parsed.hostname
                    and parsed.username is None
                    and parsed.password is None
                    and not parsed.query
                    and not parsed.fragment
                    and (port is None or 1 <= port <= 65535)
                    and (parsed.scheme == "https" or (parsed.scheme == "http" and local_host))
                )
            except ValueError:
                valid_url = False
            if not valid_url:
                errors.append("discourse_auth.url must use HTTPS (HTTP is allowed only for localhost/loopback)")

        if len(secret) < 32:
            errors.append("discourse_auth.sso_secret must be at least 32 characters")
        if not api_key:
            errors.append("discourse_auth.api_key is required for security enrichment")
        if not api_username:
            errors.append("discourse_auth.api_username must not be empty")

        organizer_error = None
        if organizer_slug and not re.fullmatch(r"[a-z0-9-]+", organizer_slug):
            organizer_error = "discourse_auth.organizer must be a valid Pretix organizer slug"
        return cls(
            discourse_url=url.rstrip("/"),
            discourse_secret=secret,
            api_key=api_key,
            api_username=api_username,
            organizer_slug=organizer_slug,
            api_timeout=api_timeout,
            errors=tuple(errors),
            organizer_error=organizer_error,
        )


SETTINGS = PluginSettings.load()
for config_error in SETTINGS.errors:
    logger.error(config_error)
if SETTINGS.organizer_error:
    logger.error(SETTINGS.organizer_error)


class DiscourseAuthBackend(BaseAuthBackend):
    identifier = "discourse"
    verbose_name = _("Log in with Discourse")

    @property
    def visible(self):
        return not SETTINGS.errors

    def authentication_url(self, request):
        if not self.visible:
            return None

        nonce = secrets.token_urlsafe(32)
        request.session["discourse_sso_nonce"] = nonce
        request.session["discourse_sso_nonce_created"] = time.time()

        return_url = request.build_absolute_uri(reverse("plugins:pretix_discourse_auth:return"))
        payload = f"nonce={nonce}&return_sso_url={return_url}&require_2fa=true"
        payload_b64 = base64.b64encode(payload.encode("utf-8")).decode("utf-8")
        sig = hmac.new(
            SETTINGS.discourse_secret.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        query = urlencode({"sso": payload_b64, "sig": sig})
        return f"{SETTINGS.discourse_url}/session/sso_provider?{query}"
