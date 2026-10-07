import base64
import hashlib
import hmac
import logging
import re
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
STAFF_GROUP = 'meetup-staff'
ORGANIZERS_GROUP_RE = re.compile(r'^meetup-organisers-([a-z]+)$')
TEAM_TEMPLATE = 'Ansible Meetup Organisers - {city}'
API_TIMEOUT = int(config.get('discourse_auth', 'api_timeout', fallback='10'))
ORGANIZER_SLUG = config.get('discourse_auth', 'organizer', fallback='')

RTBF_EMAIL_SUFFIX = '@anonymized.invalid'
NONCE_MAX_AGE_SECONDS = 600

logger = logging.getLogger(__name__)

_LOGIN_URL = 'control:auth.login'

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

    if not saved_nonce:
        logger.warning("Nonce missing from session (session expired or new browser), ip=%s", request.META.get('REMOTE_ADDR'))
        messages.error(request, _('Session expired or invalid nonce. Please try again.'))
        return redirect(reverse(_LOGIN_URL))

    if not hmac.compare_digest(parsed_sso.get('nonce', ''), saved_nonce):
        logger.warning("Nonce mismatch (possible replay or tampering), ip=%s", request.META.get('REMOTE_ADDR'))
        messages.error(request, _('Session expired or invalid nonce. Please try again.'))
        return redirect(reverse(_LOGIN_URL))

    if nonce_created is None or (time.time() - nonce_created) > NONCE_MAX_AGE_SECONDS:
        nonce_age = int(time.time() - nonce_created) if nonce_created else -1
        logger.warning("Nonce expired (age=%ds, max=%ds), ip=%s", nonce_age, NONCE_MAX_AGE_SECONDS, request.META.get('REMOTE_ADDR'))
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
    # Discard every claim except the exact staff name and exact city-group form.
    allowed_groups = {
        group
        for group in parsed_sso.get('groups', '').split(',')
        if group == STAFF_GROUP or ORGANIZERS_GROUP_RE.fullmatch(group)
    }
    organizer_groups = [
        match for group in allowed_groups
        if (match := ORGANIZERS_GROUP_RE.fullmatch(group))
    ]
    cities = [match.group(1).title() for match in organizer_groups]

    is_staff_group_member = STAFF_GROUP in allowed_groups
    privileged = is_staff_group_member or bool(organizer_groups)

    logger.info(
        "Identity extracted: external_id=%s, username=%s, groups=%d, is_staff=%s, privileged=%s",
        external_id, username, len(allowed_groups), is_staff_group_member, privileged
    )

    # Step 7: Require affirmative proof that DiscourseConnect completed the
    # required challenge. A configured factor alone is not evidence of use.
    if privileged and parsed_sso.get('confirmed_2fa') != 'true':
        logger.warning("DiscourseConnect did not attest 2FA for privileged user, external_id=%s", external_id)
        messages.error(request, _('Privileged account blocked: Discourse did not confirm two-factor authentication.'))
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

    try:
        admin_url = f"{DISCOURSE_URL.rstrip('/')}/admin/users/{urllib.parse.quote(str(external_id))}.json"
        resp = requests.get(
            admin_url,
            headers={'Api-Key': API_KEY, 'Api-Username': API_USER},
            timeout=API_TIMEOUT,
            allow_redirects=False,
        )

        if resp.status_code == 200:
            try:
                raw_data = resp.json()
            except ValueError:
                logger.error("Enrichment API returned invalid JSON, url=%s", admin_url)
                messages.error(request, _('Could not verify security status with Discourse. Please try again later.'))
                return redirect(reverse(_LOGIN_URL))

            if not isinstance(raw_data, dict):
                logger.error("Enrichment API returned a non-object response, url=%s", admin_url)
                messages.error(request, _('Could not verify security status with Discourse. Please try again later.'))
                return redirect(reverse(_LOGIN_URL))

            response_username = raw_data.get('username')
            response_id = raw_data.get('id')
            status_fields = ('silenced_till', 'suspended_till')
            if (
                str(response_id) != str(external_id)
                or not isinstance(response_username, str)
                or not response_username
                or any(
                    field in raw_data and raw_data[field] is not None and not isinstance(raw_data[field], str)
                    for field in status_fields
                )
            ):
                logger.error("Enrichment API response has invalid identity or moderation fields, url=%s", admin_url)
                messages.error(request, _('Could not verify security status with Discourse. Please try again later.'))
                return redirect(reverse(_LOGIN_URL))

            api_data = raw_data
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

    # Resolve every claimed organiser team before creating or changing the user.
    organizer = _get_organizer()
    expected_team_names = [TEAM_TEMPLATE.format(city=city) for city in cities]
    if expected_team_names:
        if organizer is None:
            logger.error("Cannot validate organiser teams; Pretix organizer is unavailable")
            messages.error(request, _('Could not verify organiser access with Pretix. Please try again later.'))
            return redirect(reverse(_LOGIN_URL))
        found_team_names = set(
            Team.objects.filter(organizer=organizer, name__in=expected_team_names)
            .values_list('name', flat=True)
        )
        missing_teams = set(expected_team_names) - found_team_names
        if missing_teams:
            logger.error("Organiser group has no matching Pretix team(s): %s", sorted(missing_teams))
            messages.error(request, _('Could not verify organiser access with Pretix. Please contact an administrator.'))
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
    if organizer is not None:
        with transaction.atomic():
            if expected_team_names:
                teams_to_join = Team.objects.filter(organizer=organizer, name__in=expected_team_names)
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
