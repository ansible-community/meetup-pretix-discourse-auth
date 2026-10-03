import base64
import hashlib
import hmac
import urllib.parse
from urllib.parse import parse_qsl
import requests
import logging

from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from pretix.base.models import User, Team
from pretix.base.models.auth import EmailAddressTakenError
from pretix.control.views.auth import process_login
from pretix.settings import config

DISCOURSE_URL = config.get('discourse_auth', 'url', fallback='')
DISCOURSE_SECRET = config.get('discourse_auth', 'sso_secret', fallback='')
API_KEY = config.get('discourse_auth', 'api_key', fallback='')
API_USER = config.get('discourse_auth', 'api_username', fallback='system')
HOST_PREFIX = config.get('discourse_auth', 'host_prefix', fallback='meetup-host').lower()
TEAM_TEMPLATE = config.get('discourse_auth', 'team_template', fallback='Ansible Meetup Staff - {city}')
ENFORCE_2FA = config.get('discourse_auth', 'enforce_2fa_privileged', fallback='true').lower() == 'true'

logger = logging.getLogger(__name__)

def return_view(request):
    sso = request.GET.get('sso')
    sig = request.GET.get('sig')

    if not sso or not sig:
        messages.error(request, _('Invalid response from Discourse.'))
        return redirect(reverse('control:auth.login'))

    # 1. Signature Verification (Constant time)
    expected_sig = hmac.new(
        DISCOURSE_SECRET.encode('utf-8'),
        sso.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(sig, expected_sig):
        messages.error(request, _('Signature mismatch. Authentication failed.'))
        return redirect(reverse('control:auth.login'))

    # 2. Decode Payload
    try:
        decoded_sso = base64.b64decode(sso).decode('utf-8')
        parsed_sso = dict(parse_qsl(decoded_sso))
    except Exception:
        messages.error(request, _('Could not decode Discourse response.'))
        return redirect(reverse('control:auth.login'))

    if parsed_sso.get('failed') == 'true':
        messages.error(request, _('Discourse authentication failed or was cancelled.'))
        return redirect(reverse('control:auth.login'))

    # 3. Nonce Verification (Replay protection)
    saved_nonce = request.session.pop('discourse_sso_nonce', None)
    if not saved_nonce or not hmac.compare_digest(parsed_sso.get('nonce', ''), saved_nonce):
        messages.error(request, _('Session expired or invalid nonce. Please try again.'))
        return redirect(reverse('control:auth.login'))

    # 4. Extract Identity & Groups
    external_id = parsed_sso.get('external_id')
    email = parsed_sso.get('email', '').lower()
    username = parsed_sso.get('username', '').lower()
    name = parsed_sso.get('name', '') or parsed_sso.get('username', '')
    is_admin = parsed_sso.get('admin') == 'true'

    groups_set = {g for g in parsed_sso.get('groups', '').split(',') if g}
    host_groups = [g for g in groups_set if g.lower().startswith(HOST_PREFIX)]
    cities = [g.split('-', 2)[-1].title() for g in host_groups]
    privileged = is_admin or bool(host_groups)

    if not external_id or not email:
        messages.error(request, _('Incomplete identity data received.'))
        return redirect(reverse('control:auth.login'))

    # 5. Enrichment via Discourse Admin API
    twofa_enabled, silenced, suspended, rtbf = False, False, False, False

    # RTBF Heuristic
    if email.endswith('@example.invalid') or username.startswith('anon') or name.lower() == 'anonymous':
        rtbf = True

    if API_KEY:
        try:
            admin_url = f"{DISCOURSE_URL.rstrip('/')}/admin/users/{urllib.parse.quote(str(external_id))}.json"
            resp = requests.get(admin_url, headers={'Api-Key': API_KEY, 'Api-Username': API_USER}, timeout=10)
            if resp.status_code == 200:
                api_data = resp.json().get('user', resp.json())
                twofa_enabled = bool(api_data.get('second_factor_enabled'))
                silenced = bool(api_data.get('silenced'))
                suspended = bool(api_data.get('suspended'))
        except requests.RequestException:
            # Fail closed on 2FA if API is unreachable and user is privileged
            messages.error(request, _('Could not verify security status with Discourse. Please try again later.'))
            return redirect(reverse('control:auth.login'))

    # 6. Apply Policy (Blocking)
    if silenced or suspended:
        messages.error(request, _('Account blocked: Moderation (Silenced/Suspended).'))
        return redirect(reverse('control:auth.login'))

    if rtbf:
        messages.error(request, _('Account blocked: Anonymized/RTBF status detected.'))
        return redirect(reverse('control:auth.login'))

    if ENFORCE_2FA and privileged and not twofa_enabled:
        messages.error(request, _('Privileged account blocked: Please enable 2FA in your Discourse security settings.'))
        return redirect(reverse('control:auth.login'))

    # 7. Provision & Update Pretix User
    try:
        user = User.objects.get_or_create_for_backend(
            'discourse',
            external_id,
            email,
            set_always={'fullname': name},
            set_on_creation={}
        )
    except EmailAddressTakenError:
        messages.error(request, _('Email conflict: Another user claims this email.'))
        return redirect(reverse('control:auth.login'))

    # Update is_staff if changed
    if user.is_staff != is_admin:
        user.is_staff = is_admin
        user.save(update_fields=['is_staff'])

# 8. Team Sync
    logger.info(f"DiscourseAuth Team Sync: Raw groups from payload: {parsed_sso.get('groups', '')}")
    logger.info(f"DiscourseAuth Team Sync: Derived cities: {cities}")

    expected_team_names = [TEAM_TEMPLATE.format(city=city) for city in cities]
    logger.info(f"DiscourseAuth Team Sync: Looking for exact team names: {expected_team_names}")

    if expected_team_names:
        teams_to_join = Team.objects.filter(name__in=expected_team_names)
        found_team_names = [t.name for t in teams_to_join]
        logger.info(f"DiscourseAuth Team Sync: Found in Pretix DB: {found_team_names}")

        for team in teams_to_join:
            team.members.add(user)
            logger.info(f"DiscourseAuth Team Sync: Added user to {team.name}")

    # Remove user from managed teams they are no longer in
    prefix_template = TEAM_TEMPLATE.split('{city}')[0].strip()
    current_teams = user.teams.filter(name__startswith=prefix_template)
    for team in current_teams:
        if team.name not in expected_team_names:
            team.members.remove(user)
            logger.info(f"DiscourseAuth Team Sync: Removed user from {team.name}")

    return process_login(request, user, keep_logged_in=False)
