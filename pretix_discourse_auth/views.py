import base64
import hashlib
import hmac
import logging
import time
import urllib.parse
from urllib.parse import parse_qsl

import requests
from django.contrib import messages
from django.db import transaction
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from pretix.base.models import Team, User
from pretix.base.models.auth import EmailAddressTakenError
from pretix.base.models.organizer import Organizer
from pretix.control.views.auth import process_login
from pretix.settings import config

DISCOURSE_URL = config.get('discourse_auth', 'url', fallback='')
DISCOURSE_SECRET = config.get('discourse_auth', 'sso_secret', fallback='')
API_KEY = config.get('discourse_auth', 'api_key', fallback='')
API_USER = config.get('discourse_auth', 'api_username', fallback='system')
HOST_PREFIX = config.get('discourse_auth', 'host_prefix', fallback='meetup-host').lower()
STAFF_GROUP = config.get('discourse_auth', 'staff_group', fallback='meetup-admin').lower()
TEAM_TEMPLATE = config.get('discourse_auth', 'team_template', fallback='Ansible Meetup Staff - {city}')
ENFORCE_2FA = config.get('discourse_auth', 'enforce_2fa_privileged', fallback='true').lower() == 'true'
API_TIMEOUT = int(config.get('discourse_auth', 'api_timeout', fallback='10'))
ORGANIZER_SLUG = config.get('discourse_auth', 'organizer', fallback='')

RTBF_EMAIL_SUFFIX = '@anonymized.invalid'
NONCE_MAX_AGE_SECONDS = 600

logger = logging.getLogger(__name__)

_LOGIN_URL = 'control:auth.login'

# Validate host_prefix is not empty
if DISCOURSE_URL and DISCOURSE_SECRET and not HOST_PREFIX:
    logger.error("discourse_auth.host_prefix must not be empty")

# Validate team_template contains {city}
if '{city}' not in TEAM_TEMPLATE:
    logger.error("discourse_auth.team_template must contain {city} — team sync will be disabled")

# Warn if staff_group collides with Discourse automatic groups
_DISCOURSE_AUTO_GROUPS = {
    'everyone', 'admins', 'moderators', 'staff', 'trust_level_0',
    'trust_level_1', 'trust_level_2', 'trust_level_3', 'trust_level_4',
}
if STAFF_GROUP in _DISCOURSE_AUTO_GROUPS:
    logger.warning(
        "discourse_auth.staff_group=%r collides with a Discourse automatic group — "
        "this may grant is_staff to unintended users", STAFF_GROUP
    )


def _get_organizer():
    if not ORGANIZER_SLUG:
        logger.error("discourse_auth.organizer is not configured — team sync disabled")
        return None
    try:
        return Organizer.objects.get(slug=ORGANIZER_SLUG)
    except Organizer.DoesNotExist:
        logger.error("discourse_auth.organizer=%r not found in pretix", ORGANIZER_SLUG)
        return None


def return_view(request):
    sso = request.GET.get('sso')
    sig = request.GET.get('sig')

    if not sso or not sig:
        logger.warning("SSO callback missing sso or sig parameter, ip=%s", request.META.get('REMOTE_ADDR'))
        messages.error(request, _('Invalid response from Discourse.'))
        return redirect(reverse(_LOGIN_URL))

    # Step 2: Signature verification (constant-time)
    # Do NOT strip whitespace from sso — trailing newline is part of signed content
    expected_sig = hmac.new(
        DISCOURSE_SECRET.encode('utf-8'),
        sso.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(sig, expected_sig):
        logger.warning("Signature mismatch, ip=%s, sig=%s...", request.META.get('REMOTE_ADDR'), sig[:8])
        messages.error(request, _('Signature mismatch. Authentication failed.'))
        return redirect(reverse(_LOGIN_URL))

    # Step 3: Decode payload
    try:
        decoded_sso = base64.b64decode(sso).decode('utf-8')
        parsed_sso = dict(parse_qsl(decoded_sso))
    except Exception:
        logger.warning("Failed to decode SSO payload, ip=%s", request.META.get('REMOTE_ADDR'))
        messages.error(request, _('Could not decode Discourse response.'))
        return redirect(reverse(_LOGIN_URL))

    if parsed_sso.get('failed') == 'true':
        logger.info("Discourse SSO cancelled by user, ip=%s", request.META.get('REMOTE_ADDR'))
        messages.error(request, _('Discourse authentication failed or was cancelled.'))
        return redirect(reverse(_LOGIN_URL))

    # Step 4: Nonce verification (replay protection + time expiry)
    saved_nonce = request.session.pop('discourse_sso_nonce', None)
    nonce_created = request.session.pop('discourse_sso_nonce_created', None)

    if not saved_nonce or not hmac.compare_digest(parsed_sso.get('nonce', ''), saved_nonce):
        logger.warning("Nonce mismatch or missing, ip=%s", request.META.get('REMOTE_ADDR'))
        messages.error(request, _('Session expired or invalid nonce. Please try again.'))
        return redirect(reverse(_LOGIN_URL))

    if nonce_created is None or (time.time() - nonce_created) > NONCE_MAX_AGE_SECONDS:
        logger.warning("Nonce expired (age >%ds), ip=%s", NONCE_MAX_AGE_SECONDS, request.META.get('REMOTE_ADDR'))
        messages.error(request, _('Session expired or invalid nonce. Please try again.'))
        return redirect(reverse(_LOGIN_URL))

    # Step 5: Extract identity
    external_id = parsed_sso.get('external_id')
    email = parsed_sso.get('email', '').lower()
    username = parsed_sso.get('username', '').lower()
    name = parsed_sso.get('name', '') or parsed_sso.get('username', '')

    if not external_id or not email:
        logger.warning("Incomplete identity data, ip=%s", request.META.get('REMOTE_ADDR'))
        messages.error(request, _('Incomplete identity data received.'))
        return redirect(reverse(_LOGIN_URL))

    # Step 6: Group parsing
    groups_set = {g.strip() for g in parsed_sso.get('groups', '').split(',') if g.strip()}
    groups_lower = {g.lower() for g in groups_set}

    host_groups = [g for g in groups_set if g.lower().startswith(HOST_PREFIX)]
    prefix_len = len(HOST_PREFIX) + 1
    cities = []
    for g in host_groups:
        if len(g) <= len(HOST_PREFIX):
            logger.warning("Discourse group %r matches host prefix but has no city suffix — skipping", g)
            continue
        city_slug = g[prefix_len:]
        cities.append(city_slug.replace('-', ' ').title())

    is_staff_group_member = STAFF_GROUP in groups_lower
    privileged = is_staff_group_member or bool(host_groups)

    logger.info(
        "Identity extracted: external_id=%s, username=%s, groups=%d, is_staff=%s, privileged=%s",
        external_id, username, len(groups_set), is_staff_group_member, privileged
    )

    # Step 7: 2FA enforcement (protocol layer)
    if ENFORCE_2FA and privileged and parsed_sso.get('no_2fa_methods') == 'true':
        logger.warning("Privileged user has no 2FA methods, external_id=%s", external_id)
        messages.error(request, _('Privileged account blocked: Please enable 2FA in your Discourse security settings.'))
        return redirect(reverse(_LOGIN_URL))

    # Step 8: RTBF detection (email domain only)
    if email.endswith(RTBF_EMAIL_SUFFIX):
        logger.warning("RTBF/anonymized account detected, external_id=%s", external_id)
        messages.error(request, _('Account blocked: Anonymized account detected.'))
        return redirect(reverse(_LOGIN_URL))

    # Step 9: Security enrichment (Discourse Admin API) — fail secure on any error
    if not API_KEY:
        logger.error("API key not configured — cannot verify security status")
        messages.error(request, _('Could not verify security status with Discourse. Please try again later.'))
        return redirect(reverse(_LOGIN_URL))

    is_silenced = False
    is_suspended = False
    has_2fa = False

    try:
        admin_url = f"{DISCOURSE_URL.rstrip('/')}/admin/users/{urllib.parse.quote(str(external_id))}.json"
        resp = requests.get(
            admin_url,
            headers={'Api-Key': API_KEY, 'Api-Username': API_USER},
            timeout=API_TIMEOUT
        )

        if resp.status_code == 200:
            try:
                raw_data = resp.json()
            except ValueError:
                logger.error("Enrichment API returned invalid JSON, url=%s", admin_url)
                messages.error(request, _('Could not verify security status with Discourse. Please try again later.'))
                return redirect(reverse(_LOGIN_URL))

            api_data = raw_data.get('user', raw_data)
            has_2fa = bool(api_data.get('second_factor_enabled'))
            is_silenced = bool(api_data.get('silenced_till'))
            is_suspended = bool(api_data.get('suspended_till'))
        else:
            if resp.status_code in (401, 403):
                logger.error(
                    "Enrichment API returned %d — API key may be invalid or revoked, url=%s",
                    resp.status_code, admin_url
                )
            else:
                logger.error("Enrichment API returned %d, url=%s", resp.status_code, admin_url)
            messages.error(request, _('Could not verify security status with Discourse. Please try again later.'))
            return redirect(reverse(_LOGIN_URL))

    except requests.RequestException as exc:
        logger.error("Enrichment API request failed: %s, url=%s", type(exc).__name__, admin_url)
        messages.error(request, _('Could not verify security status with Discourse. Please try again later.'))
        return redirect(reverse(_LOGIN_URL))

    # Step 10: Policy enforcement
    if is_silenced:
        logger.warning("Account silenced, external_id=%s", external_id)
        messages.error(request, _('Account blocked: Moderation (silenced).'))
        return redirect(reverse(_LOGIN_URL))

    if is_suspended:
        logger.warning("Account suspended, external_id=%s", external_id)
        messages.error(request, _('Account blocked: Moderation (suspended).'))
        return redirect(reverse(_LOGIN_URL))

    if ENFORCE_2FA and privileged and not has_2fa:
        logger.warning("Privileged user without 2FA (enrichment layer), external_id=%s", external_id)
        messages.error(request, _('Privileged account blocked: Please enable 2FA in your Discourse security settings.'))
        return redirect(reverse(_LOGIN_URL))

    # Step 11: Provision & update pretix user
    try:
        user = User.objects.get_or_create_for_backend(
            'discourse',
            external_id,
            email,
            set_always={'fullname': name},
            set_on_creation={}
        )
    except EmailAddressTakenError:
        logger.warning("Email conflict during provisioning, external_id=%s, email=%s", external_id, email)
        messages.error(request, _(
            'Email conflict: Another user with this email exists. Please contact an administrator.'
        ))
        return redirect(reverse(_LOGIN_URL))

    # Step 12: Staff flag sync (group-based, NOT Discourse admin flag)
    if user.is_staff != is_staff_group_member:
        logger.warning(
            "is_staff changed: external_id=%s, %s → %s (staff_group=%s)",
            external_id, user.is_staff, is_staff_group_member, STAFF_GROUP
        )
        user.is_staff = is_staff_group_member
        user.save(update_fields=['is_staff'])

    # Step 13: Team sync (within a database transaction, scoped to organizer)
    organizer = _get_organizer()
    team_sync_enabled = organizer is not None and '{city}' in TEAM_TEMPLATE

    if team_sync_enabled:
        expected_team_names = [TEAM_TEMPLATE.format(city=city) for city in cities]

        with transaction.atomic():
            if expected_team_names:
                teams_to_join = Team.objects.filter(organizer=organizer, name__in=expected_team_names)
                found_team_names = {t.name for t in teams_to_join}

                missing_teams = set(expected_team_names) - found_team_names
                for missing in missing_teams:
                    logger.warning("Team not found for city: %r (organizer=%s)", missing, ORGANIZER_SLUG)

                for team in teams_to_join:
                    team.members.add(user)
                    logger.info("Team sync: added user %s to %r", external_id, team.name)

            prefix_template = TEAM_TEMPLATE.split('{city}')[0].strip()
            current_teams = user.teams.filter(organizer=organizer, name__startswith=prefix_template)
            for team in current_teams:
                if team.name not in expected_team_names:
                    team.members.remove(user)
                    logger.info("Team sync: removed user %s from %r", external_id, team.name)

    # Step 14: Login
    return process_login(request, user, keep_logged_in=False)
