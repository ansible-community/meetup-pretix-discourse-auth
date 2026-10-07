import base64
import binascii
import hashlib
import hmac
import logging
import math
import re
import unicodedata
import urllib.parse
import time
from urllib.parse import parse_qsl

import requests
from django.contrib import messages
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from pretix.base.models import Team, User
from pretix.base.models.auth import EmailAddressTakenError
from pretix.base.models.organizer import Organizer
from pretix.control.views.auth import process_login

from .backend import (
    NONCE_MAX_AGE_SECONDS,
    ORGANIZERS_GROUP_RE,
    ORGANISERS_GROUP_PREFIX,
    RTBF_EMAIL_SUFFIX,
    SETTINGS,
    TEAM_NAME_PREFIX,
)

logger = logging.getLogger(__name__)

_LOGIN_URL = "control:auth.login"
_EXTERNAL_ID_RE = re.compile(r"^[0-9]{1,20}$")
_USERNAME_RE = re.compile(r"^[a-z0-9_.-]{1,60}$")


def _reject(request, message, *, log_message=None):
    if log_message:
        logger.warning(log_message)
    messages.error(request, message)
    return redirect(reverse(_LOGIN_URL))


def _resolve_organizer():
    if not SETTINGS.organizer_slug or SETTINGS.organizer_error:
        logger.error("Pretix organizer configuration is missing or invalid")
        return None
    try:
        return Organizer.objects.get(slug=SETTINGS.organizer_slug)
    except Organizer.DoesNotExist:
        logger.error("Configured Pretix organizer %r does not exist", SETTINGS.organizer_slug)
        return None


def _slug_from_team_name(name):
    """Map the provisioned display name suffix to its lowercase ASCII slug."""
    suffix = name[len(TEAM_NAME_PREFIX):]
    ascii_suffix = unicodedata.normalize("NFKD", suffix).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z]", "", ascii_suffix.lower())


def _team_names_for_city_slugs(organizer, city_slugs):
    teams_by_slug = {}
    for team in Team.objects.filter(organizer=organizer, name__startswith=TEAM_NAME_PREFIX):
        slug = _slug_from_team_name(team.name)
        teams_by_slug.setdefault(slug, []).append(team.name)
    result = {}
    for slug in city_slugs:
        matches = teams_by_slug.get(slug, [])
        if len(matches) != 1:
            return None
        result[slug] = matches[0]
    return result


def _parse_sso(sso):
    decoded = base64.b64decode(sso, validate=True).decode("utf-8")
    pairs = parse_qsl(decoded, keep_blank_values=True, strict_parsing=True)
    if len(dict(pairs)) != len(pairs):
        raise ValueError("duplicate SSO parameter")
    return dict(pairs)


def return_view(request):
    sso = request.GET.get("sso")
    sig = request.GET.get("sig")
    if SETTINGS.errors:
        logger.error("Discourse auth callback reached with invalid plugin configuration")
        return _reject(request, _("Discourse authentication is not configured correctly."))

    if not sso or not sig or not re.fullmatch(r"[0-9a-f]{64}", sig):
        return _reject(request, _("Invalid response from Discourse."), log_message="Malformed SSO callback")

    expected_sig = hmac.new(
        SETTINGS.discourse_secret.encode("utf-8"), sso.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return _reject(request, _("Signature mismatch. Authentication failed."), log_message="SSO signature mismatch")

    try:
        parsed_sso = _parse_sso(sso)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return _reject(request, _("Could not decode Discourse response."), log_message="Malformed signed SSO payload")

    if parsed_sso.get("failed") == "true":
        return _reject(request, _("Discourse authentication failed or was cancelled."))

    saved_nonce = request.session.pop("discourse_sso_nonce", None)
    nonce_created = request.session.pop("discourse_sso_nonce_created", None)
    callback_nonce = parsed_sso.get("nonce")
    if (
        not isinstance(saved_nonce, str)
        or not isinstance(callback_nonce, str)
        or not hmac.compare_digest(callback_nonce, saved_nonce)
        or isinstance(nonce_created, bool)
        or not isinstance(nonce_created, (int, float))
        or not math.isfinite(nonce_created)
    ):
        return _reject(request, _("Session expired or invalid nonce."), log_message="Invalid SSO nonce state")

    nonce_age = time.time() - nonce_created
    if nonce_age < 0 or nonce_age > NONCE_MAX_AGE_SECONDS:
        return _reject(request, _("Session expired or invalid nonce."), log_message="Expired or future SSO nonce")

    # Cache.add is an atomic one-time claim on supported Django cache backends,
    # preventing two concurrent callbacks from consuming the same nonce.
    nonce_key = "discourse-sso-used:" + hashlib.sha256(saved_nonce.encode("utf-8")).hexdigest()
    if not cache.add(nonce_key, True, timeout=NONCE_MAX_AGE_SECONDS):
        return _reject(request, _("Session expired or invalid nonce."), log_message="Replayed SSO nonce")

    external_id = parsed_sso.get("external_id", "")
    raw_email = parsed_sso.get("email", "")
    raw_username = parsed_sso.get("username", "")
    name = parsed_sso.get("name") or raw_username
    if (
        not isinstance(external_id, str)
        or not isinstance(raw_email, str)
        or not isinstance(raw_username, str)
        or not isinstance(name, str)
    ):
        return _reject(request, _("Incomplete or invalid identity data received."), log_message="Invalid SSO identity fields")
    email = raw_email.lower()
    username = raw_username.lower()
    if (
        not _EXTERNAL_ID_RE.fullmatch(external_id)
        or not _USERNAME_RE.fullmatch(username)
        or len(email) > 254
        or len(name) > 200
    ):
        return _reject(request, _("Incomplete or invalid identity data received."), log_message="Invalid SSO identity fields")
    try:
        validate_email(email)
    except ValidationError:
        return _reject(request, _("Incomplete or invalid identity data received."), log_message="Invalid SSO email")

    raw_groups = parsed_sso.get("groups", "")
    if not isinstance(raw_groups, str) or len(raw_groups) > 8192:
        return _reject(request, _("Invalid group data received."), log_message="Malformed SSO group claim")
    group_names = raw_groups.split(",") if raw_groups else []
    city_slugs = set()
    for group_name in group_names:
        if group_name.startswith(ORGANISERS_GROUP_PREFIX):
            match = ORGANIZERS_GROUP_RE.fullmatch(group_name)
            if match is None:
                return _reject(request, _("Invalid organiser group data received."), log_message="Malformed organiser group claim")
            city_slugs.add(match.group(1))
    is_organizer = bool(city_slugs)

    if is_organizer and parsed_sso.get("confirmed_2fa") != "true":
        return _reject(
            request,
            _("Organiser account blocked: Discourse did not confirm two-factor authentication."),
            log_message=f"DiscourseConnect did not attest 2FA for external_id={external_id}",
        )

    if email.endswith(RTBF_EMAIL_SUFFIX):
        return _reject(request, _("Account blocked: Anonymized account detected."), log_message="RTBF account attempted SSO")

    admin_url = f"{SETTINGS.discourse_url}/admin/users/{external_id}.json"
    try:
        response = requests.get(
            admin_url,
            headers={"Api-Key": SETTINGS.api_key, "Api-Username": SETTINGS.api_username},
            timeout=SETTINGS.api_timeout,
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise requests.HTTPError(f"Unexpected HTTP status {response.status_code}")
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        logger.error("Discourse security verification failed: %s", type(exc).__name__)
        return _reject(request, _("Could not verify security status with Discourse. Please try again later."))

    if (
        not isinstance(data, dict)
        or str(data.get("id")) != external_id
        or not isinstance(data.get("username"), str)
        or not data["username"]
        or any(field in data and data[field] is not None and not isinstance(data[field], str)
               for field in ("silenced_till", "suspended_till"))
    ):
        return _reject(request, _("Could not verify security status with Discourse. Please try again later."), log_message="Malformed Discourse security response")

    if data.get("silenced_till") or data.get("suspended_till"):
        return _reject(request, _("Account blocked: Moderation status prevents login."), log_message="Moderated user attempted SSO")

    organizer = None
    expected_team_names = []
    if is_organizer:
        if SETTINGS.organizer_error:
            return _reject(request, _("Could not verify organiser access with Pretix. Please contact an administrator."), log_message=SETTINGS.organizer_error)
        organizer = _resolve_organizer()
        if organizer is None:
            return _reject(request, _("Could not verify organiser access with Pretix. Please contact an administrator."))
        team_names = _team_names_for_city_slugs(organizer, city_slugs)
        if team_names is None:
            return _reject(
                request,
                _("Could not verify organiser access with Pretix. Please contact an administrator."),
                log_message=f"One or more organiser groups have no unique Pretix team: {sorted(city_slugs)}",
            )
        expected_team_names = list(team_names.values())

    try:
        user = User.objects.get_or_create_for_backend(
            "discourse",
            external_id,
            email,
            set_always={"fullname": name},
            set_on_creation={},
        )
    except EmailAddressTakenError:
        return _reject(
            request,
            _("Email conflict: Another user with this email exists. Please contact an administrator."),
            log_message=f"Email conflict during provisioning for external_id={external_id}",
        )

    # Pretix's is_staff flag is owned exclusively by Pretix administrators.
    # Discourse claims never grant or revoke site-wide administration.
    if organizer is not None:
        with transaction.atomic():
            teams_to_join = Team.objects.filter(organizer=organizer, name__in=expected_team_names)
            for team in teams_to_join:
                team.members.add(user)
            current_teams = user.teams.filter(organizer=organizer, name__startswith=TEAM_NAME_PREFIX)
            for team in current_teams:
                if team.name not in expected_team_names:
                    team.members.remove(user)

    return process_login(request, user, keep_logged_in=False)
