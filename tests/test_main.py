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
from pretix_discourse_auth import backend
from pretix_discourse_auth.backend import CITY_TEAM_NAME_BY_SLUG

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
    monkeypatch.setattr(views.cache, "incr", Mock(return_value=1))
    monkeypatch.setattr(views, "get_client_ip", Mock(return_value="192.0.2.1"))
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


def make_callback(
    *,
    groups: str = "",
    confirmed_2fa: bool | str = False,
    email: str = EMAIL,
    username: str = USERNAME,
    name: str = "Attendee Example",
):
    nonce = "test-nonce"
    fields = {
        "nonce": nonce,
        "external_id": EXTERNAL_ID,
        "email": email,
        "username": username,
        "name": name,
        "groups": groups,
    }
    if confirmed_2fa:
        fields["confirmed_2fa"] = (
            confirmed_2fa if isinstance(confirmed_2fa, str) else "true"
        )
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


def allow_moderation_check(monkeypatch, data=None):
    response = Mock(status_code=200)
    response.json.return_value = data or {
        "id": int(EXTERNAL_ID),
        "username": USERNAME,
    }
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
    assert request.session.expiry == 0
    assert views.cache.add.called


def test_authentication_url_signs_2fa_required_payload(monkeypatch):
    monkeypatch.setattr(
        backend,
        "SETTINGS",
        SimpleNamespace(
            errors=(),
            discourse_secret=SECRET,
            discourse_url="https://forum.example.org",
        ),
    )
    monkeypatch.setattr(backend, "reverse", lambda _name: "/_discourse/login/return/")
    request = RequestFactory().get("/control/login/")
    request.session = Session()

    url = backend.DiscourseAuthBackend().authentication_url(request)
    query = url.split("?", 1)[1]
    from urllib.parse import parse_qs

    params = parse_qs(query)
    payload = base64.b64decode(params["sso"][0]).decode("utf-8")
    fields = dict(pair.split("=", 1) for pair in payload.split("&"))
    expected_sig = hmac.new(
        SECRET.encode("utf-8"), params["sso"][0].encode("utf-8"), hashlib.sha256
    ).hexdigest()

    assert fields["require_2fa"] == "true"
    assert fields["return_sso_url"] == "http://testserver/_discourse/login/return/"
    assert request.session["discourse_sso_nonce"] == fields["nonce"]
    assert params["sig"] == [expected_sig]


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


def test_tampered_signed_payload_is_rejected(callback_harness, monkeypatch):
    request = make_callback()
    request.GET = request.GET.copy()
    request.GET["sso"] = base64.b64encode(b"nonce=other").decode()
    admin_api = Mock()
    monkeypatch.setattr(views.requests, "get", admin_api)

    assert views.return_view(request) == ("redirect", "/login/")
    admin_api.assert_not_called()


def test_tampered_signature_is_rejected(callback_harness, monkeypatch):
    request = make_callback()
    request.GET = request.GET.copy()
    request.GET["sig"] = "0" * 64

    assert views.return_view(request) == ("redirect", "/login/")
    views.User.objects.get_or_create_for_backend.assert_not_called()


def test_invalid_utf8_payload_is_rejected(callback_harness, monkeypatch):
    payload = base64.b64encode(b"\xff").decode()
    signature = hmac.new(
        SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    request = RequestFactory().get(
        "/_discourse/login/return/", {"sso": payload, "sig": signature}
    )
    request.session = Session()

    assert views.return_view(request) == ("redirect", "/login/")
    views.messages.error.assert_called_once()


def test_oversized_group_claim_rejects_cleanly(callback_harness):
    request = make_callback(groups="x" * 8193)

    assert views.return_view(request) == ("redirect", "/login/")
    assert views.messages.error.called


@pytest.mark.parametrize(
    "email", ["anon123@anonymized.invalid", "ANON123@ANONYMIZED.INVALID"]
)
def test_anonymized_email_is_rejected(callback_harness, monkeypatch, email):
    request = make_callback(email=email, username="anondale")
    get_user = Mock()
    admin_api = Mock()
    monkeypatch.setattr(views.User.objects, "get_or_create_for_backend", get_user)
    monkeypatch.setattr(views.requests, "get", admin_api)

    assert views.return_view(request) == ("redirect", "/login/")
    get_user.assert_not_called()
    admin_api.assert_not_called()


def test_legitimate_anon_username_is_not_anonymized(callback_harness, monkeypatch):
    request = make_callback(username="anondale")
    allow_moderation_check(monkeypatch)
    user = make_user()
    monkeypatch.setattr(
        views.User.objects, "get_or_create_for_backend", Mock(return_value=user)
    )
    monkeypatch.setattr(views, "process_login", Mock(return_value="login-success"))

    assert views.return_view(request) == "login-success"


@pytest.mark.parametrize("nonce_age", [-1, views.NONCE_MAX_AGE_SECONDS + 1])
def test_future_and_expired_nonces_are_rejected(
    callback_harness, monkeypatch, nonce_age
):
    request = make_callback()
    request.session["discourse_sso_nonce_created"] = time.time() - nonce_age
    admin_api = Mock()
    monkeypatch.setattr(views.requests, "get", admin_api)

    assert views.return_view(request) == ("redirect", "/login/")
    admin_api.assert_not_called()


def test_replayed_nonce_is_rejected(callback_harness, monkeypatch):
    request = make_callback()
    monkeypatch.setattr(
        views.cache,
        "add",
        Mock(
            side_effect=lambda key, *_args, **_kwargs: (
                not key.startswith("discourse-sso-used:")
            )
        ),
    )
    admin_api = Mock()
    monkeypatch.setattr(views.requests, "get", admin_api)

    assert views.return_view(request) == ("redirect", "/login/")
    admin_api.assert_not_called()


@pytest.mark.parametrize(
    ("field", "value", "expected_message", "reason"),
    [
        (
            "silenced_till",
            "2026-10-08T12:00:00Z",
            "Account blocked: Moderation (silenced).",
            "R10: Silenced user",
        ),
        (
            "suspended_till",
            "2026-10-08T12:00:00Z",
            "Account blocked: Moderation (suspended).",
            "R11: Suspended user",
        ),
    ],
)
def test_moderation_reasons_are_distinguished(
    callback_harness, monkeypatch, caplog, field, value, expected_message, reason
):
    request = make_callback()
    allow_moderation_check(
        monkeypatch,
        {"id": int(EXTERNAL_ID), "username": USERNAME, field: value},
    )
    get_user = Mock()
    monkeypatch.setattr(views.User.objects, "get_or_create_for_backend", get_user)

    assert views.return_view(request) == ("redirect", "/login/")
    assert views.messages.error.call_args.args[1] == expected_message
    assert reason in caplog.text
    get_user.assert_not_called()


@pytest.mark.parametrize("field", ["silenced_till", "suspended_till"])
@pytest.mark.parametrize("value", [42, ""])
def test_malformed_moderation_fields_fail_closed(
    callback_harness, monkeypatch, field, value
):
    request = make_callback()
    allow_moderation_check(
        monkeypatch,
        {"id": int(EXTERNAL_ID), "username": USERNAME, field: value},
    )
    get_user = Mock()
    monkeypatch.setattr(views.User.objects, "get_or_create_for_backend", get_user)

    assert views.return_view(request) == ("redirect", "/login/")
    get_user.assert_not_called()


@pytest.mark.parametrize("assertion", ["True", "TRUE", "false", ""])
def test_privileged_login_rejects_noncanonical_2fa_assertion(
    callback_harness, monkeypatch, assertion
):
    request = make_callback(confirmed_2fa=assertion)
    monkeypatch.setattr(
        views,
        "_existing_user_privilege_flags",
        Mock(return_value=(False, True, False)),
    )
    admin_api = Mock()
    monkeypatch.setattr(views.requests, "get", admin_api)

    assert views.return_view(request) == ("redirect", "/login/")
    admin_api.assert_not_called()


def test_utf8_display_name_is_preserved(callback_harness, monkeypatch):
    request = make_callback()
    fields = {
        "nonce": "test-nonce",
        "external_id": EXTERNAL_ID,
        "email": EMAIL,
        "username": USERNAME,
        "name": "José Łódź",
        "groups": "",
    }
    payload = base64.b64encode(urlencode(fields).encode("utf-8")).decode()
    request.GET = request.GET.copy()
    request.GET["sso"] = payload
    request.GET["sig"] = hmac.new(
        SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    allow_moderation_check(monkeypatch)
    user = make_user()
    get_user = Mock(return_value=user)
    monkeypatch.setattr(views.User.objects, "get_or_create_for_backend", get_user)
    monkeypatch.setattr(views, "process_login", Mock(return_value="login-success"))

    assert views.return_view(request) == "login-success"
    assert get_user.call_args.kwargs["set_always"]["fullname"] == "José Łódź"


def test_rate_limit_returns_429_with_retry_after(callback_harness, monkeypatch):
    request = RequestFactory().get("/_discourse/login/return/")
    monkeypatch.setattr(views.cache, "incr", Mock(return_value=11))

    response = views._rate_limit_response(request)

    assert response.status_code == 429
    assert response["Retry-After"] == "60"


def test_bad_signature_counts_double_toward_rate_limit(callback_harness, monkeypatch):
    request = make_callback()
    request.GET = request.GET.copy()
    request.GET["sig"] = "0" * 64
    monkeypatch.setattr(views.cache, "incr", Mock(side_effect=[9, 11]))

    response = views.return_view(request)

    assert response.status_code == 429
    assert [call.args[1] for call in views.cache.incr.call_args_list] == [1, 1]


def test_rate_limiter_cache_failure_fails_closed(callback_harness, monkeypatch):
    request = RequestFactory().get("/_discourse/login/return/")
    monkeypatch.setattr(views.cache, "incr", Mock(side_effect=RuntimeError))

    response = views._rate_limit_response(request)

    assert response.status_code == 503


def test_stale_city_team_membership_is_removed(callback_harness, monkeypatch):
    request = make_callback(groups="meetup-organisers-london", confirmed_2fa=True)
    allow_moderation_check(monkeypatch)
    stale_team = SimpleNamespace(members=SimpleNamespace(remove=Mock()))
    city_team = SimpleNamespace(members=SimpleNamespace(add=Mock()))
    user_teams = Mock()

    def filter_user_teams(**kwargs):
        if kwargs.get("name") == views.STAFF_TEAM_NAME:
            return QuerySet()
        if "name__startswith" in kwargs:
            return QuerySet([stale_team])
        return QuerySet()

    user_teams.filter.side_effect = filter_user_teams
    user = SimpleNamespace(
        is_staff=False,
        teams=user_teams,
        refresh_from_db=Mock(),
    )
    monkeypatch.setattr(
        views.User.objects, "get_or_create_for_backend", Mock(return_value=user)
    )
    monkeypatch.setattr(
        views.Team,
        "objects",
        SimpleNamespace(filter=Mock(return_value=QuerySet([city_team]))),
    )
    monkeypatch.setattr(views, "process_login", Mock(return_value="login-success"))

    assert views.return_view(request) == "login-success"
    city_team.members.add.assert_called_once_with(user)
    stale_team.members.remove.assert_called_once_with(user)


def test_nonce_mismatch_counts_double_toward_rate_limit(callback_harness, monkeypatch):
    request = make_callback()
    request.session["discourse_sso_nonce"] = "different-nonce"
    monkeypatch.setattr(views.cache, "incr", Mock(side_effect=[1, 2]))

    assert views.return_view(request) == ("redirect", "/login/")
    assert [call.args[1] for call in views.cache.incr.call_args_list] == [1, 1]


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
