from __future__ import annotations

import base64
import hashlib
import hmac
import pytest
import time
from django.test import RequestFactory
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlencode

from pretix_discourse_auth import views
from pretix_discourse_auth.backend import (
    AUTH_SESSION_IDLE_TIMEOUT_SECONDS,
    CITY_TEAM_NAME_BY_SLUG,
)

SECRET = "test-sso-secret-that-is-long-enough-to-sign-callbacks"
EXTERNAL_ID = "123"
EMAIL = "attendee@example.org"
USERNAME = "attendee"


class Session(dict):
    def set_expiry(self, seconds: int) -> None:
        self.expiry = seconds


class QuerySet(list):
    def count(self) -> int:
        return len(self)

    def exists(self) -> bool:
        return bool(self)


@pytest.fixture
def callback_harness(monkeypatch):
    settings = SimpleNamespace(
        errors=(),
        organizer_error=None,
        organizer_slug="ansible-meetups",
        discourse_secret=SECRET,
        discourse_url="https://forum.example.org",
        api_key="api-key",
        api_username="system",
        api_timeout=10,
    )
    monkeypatch.setattr(views, "SETTINGS", settings)
    monkeypatch.setattr(views.cache, "add", Mock(return_value=True))
    monkeypatch.setattr(views.messages, "error", Mock())
    monkeypatch.setattr(views, "reverse", lambda _name: "/login/")
    monkeypatch.setattr(views, "redirect", lambda location: ("redirect", location))
    monkeypatch.setattr(views.User.objects, "get_or_create_for_backend", Mock())
    monkeypatch.setattr(
        views,
        "_existing_user_privilege_flags",
        Mock(return_value=(False, False, False)),
    )
    monkeypatch.setattr(views, "_resolve_organizer", Mock(return_value=object()))
    monkeypatch.setattr(
        views,
        "_team_names_for_city_slugs",
        Mock(return_value={"london": CITY_TEAM_NAME_BY_SLUG["london"]}),
    )
    return settings


def make_callback(*, groups: str = "", confirmed_2fa: bool = False):
    nonce = "test-nonce"
    fields = {
        "nonce": nonce,
        "external_id": EXTERNAL_ID,
        "email": EMAIL,
        "username": USERNAME,
        "name": "Attendee Example",
        "groups": groups,
    }
    if confirmed_2fa:
        fields["confirmed_2fa"] = "true"
    payload = base64.b64encode(urlencode(fields).encode()).decode()
    signature = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    request = RequestFactory().get(
        "/_discourse/login/return/", {"sso": payload, "sig": signature}
    )
    request.session = Session(
        discourse_sso_nonce=nonce,
        discourse_sso_nonce_created=time.time(),
    )
    return request


def allow_moderation_check(monkeypatch):
    response = Mock(status_code=200)
    response.json.return_value = {"id": int(EXTERNAL_ID), "username": USERNAME}
    monkeypatch.setattr(views.requests, "get", Mock(return_value=response))


def make_user():
    teams = Mock()
    teams.filter.side_effect = lambda **_kwargs: QuerySet()
    return SimpleNamespace(is_staff=False, teams=teams, refresh_from_db=Mock())


def test_attendee_login_succeeds_without_organizer_configuration(
    callback_harness, monkeypatch
):
    callback_harness.organizer_error = "bad organizer config"
    user = make_user()
    allow_moderation_check(monkeypatch)
    monkeypatch.setattr(
        views.User.objects, "get_or_create_for_backend", Mock(return_value=user)
    )
    login = Mock(return_value="login-success")
    monkeypatch.setattr(views, "process_login", login)

    request = make_callback()
    assert views.return_view(request) == "login-success"
    login.assert_called_once_with(request, user, keep_logged_in=False)
    assert request.session.expiry == AUTH_SESSION_IDLE_TIMEOUT_SECONDS
    assert views.cache.add.called


def test_organizer_claim_requires_signed_2fa_before_api_or_user_writes(
    callback_harness, monkeypatch
):
    request = make_callback(groups="meetup-organisers-london")
    get_user = Mock()
    admin_api = Mock()
    monkeypatch.setattr(views.User.objects, "get_or_create_for_backend", get_user)
    monkeypatch.setattr(views.requests, "get", admin_api)

    assert views.return_view(request) == ("redirect", "/login/")
    get_user.assert_not_called()
    admin_api.assert_not_called()
    views.messages.error.assert_called_once()


def test_bad_admin_api_credentials_fail_closed_before_user_creation(
    callback_harness, monkeypatch
):
    request = make_callback()
    response = Mock(status_code=403)
    monkeypatch.setattr(views.requests, "get", Mock(return_value=response))
    get_user = Mock()
    monkeypatch.setattr(views.User.objects, "get_or_create_for_backend", get_user)

    assert views.return_view(request) == ("redirect", "/login/")
    get_user.assert_not_called()


def test_organizer_login_resolves_team_and_requires_2fa(callback_harness, monkeypatch):
    request = make_callback(groups="meetup-organisers-london", confirmed_2fa=True)
    allow_moderation_check(monkeypatch)
    user = make_user()
    monkeypatch.setattr(
        views.User.objects, "get_or_create_for_backend", Mock(return_value=user)
    )
    team = SimpleNamespace(members=SimpleNamespace(add=Mock()))
    monkeypatch.setattr(
        views.Team,
        "objects",
        SimpleNamespace(filter=Mock(return_value=QuerySet([team]))),
    )
    login = Mock(return_value="login-success")
    monkeypatch.setattr(views, "process_login", login)

    assert views.return_view(request) == "login-success"
    team.members.add.assert_called_once_with(user)
    login.assert_called_once_with(request, user, keep_logged_in=False)


def test_missing_claimed_city_team_rejects_before_user_creation(
    callback_harness, monkeypatch
):
    request = make_callback(groups="meetup-organisers-london", confirmed_2fa=True)
    allow_moderation_check(monkeypatch)
    monkeypatch.setattr(views, "_team_names_for_city_slugs", Mock(return_value=None))
    get_user = Mock()
    monkeypatch.setattr(views.User.objects, "get_or_create_for_backend", get_user)

    assert views.return_view(request) == ("redirect", "/login/")
    get_user.assert_not_called()


def test_parser_rejects_duplicate_signed_parameters():
    payload = base64.b64encode(b"nonce=first&nonce=second").decode()

    with pytest.raises(ValueError, match="duplicate"):
        views._parse_sso(payload)


@pytest.mark.parametrize(
    "privilege_flags",
    [
        (True, False, False),
        (False, True, False),
        (False, False, True),
    ],
    ids=["pretix-site-staff", "pretix-staff-team", "existing-city-team"],
)
def test_every_existing_privileged_user_requires_discord_2fa(
    callback_harness,
    monkeypatch,
    privilege_flags,
):
    request = make_callback()
    monkeypatch.setattr(
        views,
        "_existing_user_privilege_flags",
        Mock(return_value=privilege_flags),
    )
    admin_api = Mock()
    monkeypatch.setattr(views.requests, "get", admin_api)

    assert views.return_view(request) == ("redirect", "/login/")
    admin_api.assert_not_called()
    views.User.objects.get_or_create_for_backend.assert_not_called()
