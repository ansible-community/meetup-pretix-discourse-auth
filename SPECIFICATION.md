# Technical Specification: pretix-discourse-auth

**Version:** 2.0  
**Date:** 2026-10-05  
**Status:** DRAFT — all design decisions resolved. Ready for implementation review.  
**Audience:** Engineering team rebuilding from scratch  

---

## 1. Terminology

These terms are used consistently throughout this document.

| Term | Definition |
|------|-----------|
| **Consumer** | The application that delegates authentication to an external identity provider. In this system, **pretix** (via this plugin) is the consumer. Sometimes called "client" or "relying party." |
| **Provider** | The application that authenticates users and asserts their identity. In this system, **Discourse** (`forum.ansible.com`) is the provider. Sometimes called "identity provider" or "IdP." |
| **DiscourseConnect** | The SSO protocol used between consumer and provider. Formerly called "Discourse SSO." Uses HMAC-SHA256 signed payloads exchanged via browser redirects. |
| **SSO payload** | The base64-encoded, HMAC-signed query string exchanged between consumer and provider. Contains identity fields (`external_id`, `email`, `groups`, etc.). |
| **Privileged user** | A user who belongs to the staff group OR any host group. Privileged users are held to higher security requirements (2FA, enrichment checks). |
| **Enrichment** | A server-to-server call from pretix to Discourse's Admin API to retrieve security metadata (silenced, suspended status) not available in the SSO payload. |
| **RTBF** | Right To Be Forgotten. Refers to a Discourse user whose account has been anonymized. Discourse replaces the email with `{username}@anonymized.invalid`, changes the username to `anon{digits}`, and destroys all auth records. |
| **Staff group** | A dedicated Discourse group (configurable, default `meetup-admin`) whose members receive pretix `is_staff` access. Distinct from the Discourse `admin` flag. |
| **Host group** | A Discourse group whose name starts with `HOST_PREFIX` (default `meetup-host`), identifying meetup organizers for a specific city. |
| **Managed team** | A pretix Team whose name matches the `TEAM_TEMPLATE` pattern. The plugin manages membership of these teams; it never creates or deletes them. |
| **Fail secure** | When a security check cannot be completed (API error, missing config, ambiguous state), deny access rather than allow it. This is the default posture for all decisions in this system. |

### Design principle: fail secure

This system prioritizes security over availability. When in doubt:

- Missing or invalid configuration **blocks the auth backend from appearing** (not a silent degradation).
- API errors during enrichment **block login** (not a silent pass-through).
- Unknown state (e.g., 2FA status unverifiable) is treated as **failing the check**.
- It is acceptable to block a legitimate user who must then retry or contact an admin. It is **not acceptable** to allow access due to misconfiguration, transient errors, or ambiguous state.

---

## 2. Executive Summary

### What it does

A pretix plugin that replaces pretix's built-in username/password login for the **pretix control panel** (the admin/organizer interface) with Single Sign-On via a Discourse forum — specifically `forum.ansible.com`.

When an operator clicks "Log in with Discourse," they are redirected to Discourse, authenticate there, and are redirected back. The plugin then:

1. Verifies the cryptographic SSO payload.
2. Provisions or updates a pretix user account.
3. Enforces security policies (2FA requirements, moderation blocks, RTBF detection).
4. Syncs Discourse group memberships to pretix team assignments — mapping meetup host groups (e.g., `meetup-host-berlin`) to pretix teams (e.g., `Ansible Meetup Organisers - Berlin`).

### Core value proposition

Ansible community meetup organizers manage events through pretix. Rather than maintaining separate credentials, they log in with the same Discourse identity they already use on `forum.ansible.com`. Their Discourse group memberships automatically determine which pretix teams (and therefore which events/organizers) they can manage — no manual pretix user administration needed.

### Trust model

Discourse is the **provider** and **source of truth** for:
- User identity (email, username, display name)
- Group memberships (which cities a host manages, and whether they hold pretix staff access)
- Moderation status (silenced, suspended)
- 2FA enforcement (via `require_2fa` in the DiscourseConnect protocol)

Pretix is the **consumer**. It trusts Discourse's assertions about users, subject to its own policy layer (enrichment checks, fail-secure defaults). Pretix staff access is controlled by membership in a dedicated Discourse group (configurable, not the Discourse admin flag).

---

## 3. Core Workflows

### 3.1 Login Initiation (pretix → Discourse)

**Trigger:** User clicks the "Log in with Discourse" button on the pretix control panel login page.

**Steps:**

1. The plugin's auth backend generates a cryptographically random nonce (32 bytes, URL-safe base64).
2. The nonce and a timestamp (`time.time()`) are stored in the Django session under keys `discourse_sso_nonce` and `discourse_sso_nonce_created`.
3. A payload string is constructed: `nonce=<nonce>&return_sso_url=<callback_url>&require_2fa=true`.
4. The payload is base64-encoded.
5. An HMAC-SHA256 signature is computed over the base64 payload using the shared SSO secret.
6. The user's browser is redirected to `{DISCOURSE_URL}/session/sso_provider?sso={payload_b64}&sig={sig}`.

**`require_2fa=true`:** Always sent. Discourse prompts the user for 2FA during authentication (if the user has 2FA configured). If the user has no 2FA methods, Discourse returns `no_2fa_methods=true` in the response and lets the consumer decide. This is the first layer of 2FA enforcement; the enrichment call (Step 9) provides the second. See [Appendix A](#appendix-a-discourseconnect-protocol-reference) for protocol details.

**Callback URL format:** `https://{pretix_host}/_discourse/login/return/` (resolved via Django's `reverse()` using the named URL `plugins:pretix_discourse_auth:return`).

### 3.2 SSO Callback (Discourse → pretix)

**Trigger:** Discourse redirects the user's browser back to pretix's callback URL with `?sso=...&sig=...` query parameters.

**Steps (executed sequentially — each failure redirects to the login page with an error message):**

All rejection scenarios are consolidated in the [Rejection Matrix](#34-rejection-matrix) below.

#### Step 1: Parameter validation
- Verify both `sso` and `sig` GET parameters are present.

#### Step 2: Signature verification
- Compute HMAC-SHA256 over the **raw** `sso` parameter value using the shared secret. **Do not strip whitespace** — the value may contain a trailing newline that is part of the signed content (see [Appendix A](#appendix-a-discourseconnect-protocol-reference)).
- Compare against the provided `sig` using constant-time comparison (`hmac.compare_digest`).

#### Step 3: Payload decoding
- Base64-decode the `sso` parameter.
- Parse as a URL query string into key-value pairs.
- If the payload contains `failed=true`, reject (user cancelled or Discourse denied).

#### Step 4: Nonce verification (replay protection)
- Pop `discourse_sso_nonce` and `discourse_sso_nonce_created` from the session (single-use: once popped, cannot be reused).
- Compare the payload's `nonce` against the saved nonce using constant-time comparison.
- Verify the nonce was created less than **10 minutes** ago (Discourse expires nonces after 30 minutes on its side; 10 minutes provides margin). Reject if stale.

#### Step 5: Identity extraction
Extract from the decoded payload:

| Payload field    | Required | Processing                        | Maps to               |
|------------------|----------|-----------------------------------|-----------------------|
| `external_id`    | Yes      | Used as-is (Discourse `user.id`)  | Auth backend identifier |
| `email`          | Yes      | Lowercased                        | User email            |
| `username`       | No       | Lowercased                        | RTBF heuristic input  |
| `name`           | No       | Falls back to `username` if empty | User fullname         |
| `groups`         | No       | Comma-separated string → set      | Team sync + staff sync input |
| `no_2fa_methods` | No       | `"true"` if user has no 2FA configured | 2FA enforcement (protocol layer) |

The Discourse `admin` flag is **not used**. Staff status is determined by group membership (see Step 10).

If `external_id` or `email` is missing/empty, reject.

#### Step 6: Group parsing
- The `groups` payload includes **all** Discourse groups (custom and automatic — `trust_level_0`, `staff`, `everyone`, etc.). Filter those whose lowercased name starts with `HOST_PREFIX` (default: `meetup-host`).
- For each matching group, extract the city portion: everything after the prefix and its separator hyphen.
- Groups that match the prefix exactly (no city suffix) are skipped with a log warning.
- The city slug is normalized: hyphens replaced with spaces, then title-cased.
  - Example: `meetup-host-new-york` → `New York`
  - Example: `meetup-host-berlin` → `Berlin`
  - Example: `meetup-host-kuala-lumpur` → `Kuala Lumpur`
- Check whether the user belongs to the `STAFF_GROUP` (configurable, default: `meetup-admin`). This is an exact match on the group name, case-insensitive. **Warning:** Discourse has a built-in automatic group named `staff`. Do not set `staff_group` to `staff` — use a name that does not collide with Discourse automatic groups.
- A user is considered **privileged** if they belong to the staff group OR any host group.

#### Step 7: 2FA enforcement (protocol layer)

If `ENFORCE_2FA` is enabled and the user is privileged:
- Check for `no_2fa_methods=true` in the SSO payload.
- If set, reject — the user has no 2FA methods configured in Discourse.

This is the **first layer** of 2FA enforcement, handled by the DiscourseConnect protocol itself (`require_2fa=true` was sent in Step 3.1). Users who DO have 2FA were prompted by Discourse during authentication. The enrichment call (Step 9) provides the second layer.

#### Step 8: RTBF detection (heuristic)

**Constant:** `RTBF_EMAIL_SUFFIX = "@anonymized.invalid"`

A user is flagged as RTBF if their email ends with `@anonymized.invalid`. This is the email suffix Discourse assigns during anonymization (verified in source: `UserAnonymizer::EMAIL_SUFFIX = "@anonymized.invalid"`).

Username and display name heuristics are **not used** — they produce false positives for legitimate usernames. The email domain is sufficient: Discourse destroys all auth records during anonymization, so an anonymized user cannot reach this point in practice. This check is defense-in-depth.

#### Step 9: Security enrichment (Discourse Admin API)

**Precondition:** `API_KEY` must be configured. If not configured, the auth backend refuses to register at startup (see [Section 5.1 Config Validation](#51-configuration-validation)).

- Call `GET {DISCOURSE_URL}/admin/users/{external_id}.json` with headers `Api-Key` and `Api-Username`.
- Timeout: 10 seconds (configurable via `api_timeout`).
- Parse response JSON once, store in a local variable. The Discourse Admin API returns the user object directly (`root: false`), so `api_data = raw_data` — no `raw_data.get('user', raw_data)` wrapper needed.

**On HTTP 200, extract:**

| API field | Type | Interpretation |
|-----------|------|----------------|
| `second_factor_enabled` | boolean | `true` if user has 2FA configured. Second layer check — redundant with Step 7 but provides defense-in-depth (catches cases where `require_2fa` was not sent or Discourse behavior changes). |
| `silenced_till` | datetime or absent | **Present only when user is silenced.** If the key exists and is non-null, the user is silenced. If absent, the user is not silenced. |
| `suspended_till` | datetime or absent | **Present only when user is suspended.** If the key exists and is non-null, the user is suspended. Note: suspended users cannot complete SSO (Discourse blocks login), so this is defense-in-depth. |

**Critical implementation note:** The Discourse Admin API does **not** return boolean `silenced` or `suspended` fields. It returns `silenced_till` and `suspended_till` as datetime values, **only when the user is silenced/suspended**. Check for the presence and non-null value of these keys:

```
is_silenced = bool(api_data.get('silenced_till'))
is_suspended = bool(api_data.get('suspended_till'))
has_2fa = bool(api_data.get('second_factor_enabled'))
```

**`second_factor_enabled` suppression in SSO mode:** When Discourse is configured as an SSO provider (`enable_discourse_connect` is true), the `AdminUserListSerializer`'s `include_second_factor_enabled?` guard returns `false`. The `AdminDetailedUserSerializer` overrides the value but may inherit the suppression. In practice, this means `second_factor_enabled` may be **absent** from the API response in SSO-enabled deployments. `api_data.get('second_factor_enabled')` returns `None` → `bool(None)` = `False`, causing the enrichment-layer 2FA check to fail-secure (block privileged users). The **protocol-layer check** (Step 7, `no_2fa_methods`) is the effective 2FA enforcement; the enrichment check is defense-in-depth that may be overly strict in SSO deployments.

**On any error (network, timeout, non-200, invalid JSON):** Fail secure — reject login with "Could not verify security status with Discourse." All API errors are treated identically: the enrichment check cannot be completed, so access is denied. There is no distinction between network errors and HTTP errors. See [Rejection Matrix R9](#34-rejection-matrix).

#### Step 10: Policy enforcement

Evaluated in order; first match blocks login:

| Condition | Error message |
|-----------|---------------|
| User is silenced (from enrichment) | "Account blocked: Moderation (silenced)." |
| User is suspended (from enrichment, defense-in-depth) | "Account blocked: Moderation (suspended)." |
| User is flagged RTBF (from Step 8) | "Account blocked: Anonymized account." |
| `ENFORCE_2FA` + privileged + no 2FA (enrichment `second_factor_enabled=false`) | "Privileged account blocked: Please enable 2FA in Discourse." |

Note: Step 7 (protocol-layer 2FA) already blocked users with `no_2fa_methods=true` before enrichment. Step 10's 2FA check catches the edge case where Discourse's protocol response and API response disagree, or where `require_2fa` was not sent.

#### Step 11: User provisioning

- Call pretix's `User.objects.get_or_create_for_backend('discourse', external_id, email, set_always={'fullname': name}, set_on_creation={})`.
  - The method matches on `('discourse', external_id)`, not email.
  - On every login: updates `fullname` and **email** (the email update is hardcoded in pretix's `get_or_create_for_backend` — it always sets `email` via `set_always`).
  - On first creation: no additional fields set.
- **On `EmailAddressTakenError`:** Reject with "Email conflict: Another user with this email exists on a different auth backend." This is raised when the user's Discourse email matches an existing pretix user linked to a different auth backend. The email update cannot be skipped — it is hardcoded in pretix's `get_or_create_for_backend`. Admin intervention is required to resolve the conflict.

#### Step 12: Staff flag sync (group-based)

- Determine whether the user should have pretix `is_staff` by checking membership in the configured `STAFF_GROUP` Discourse group (default: `meetup-admin`).
- If the user's current `is_staff` value does not match, update it.
- This is a **write-on-every-login** operation, not an event-driven sync.
- The Discourse `admin` flag is explicitly **not used** — it maps to Discourse forum administration, which is a different trust domain from pretix infrastructure access.
- `is_staff` in pretix grants **site-wide admin access** across all organizers (verified in source: `staff_member_required` decorator).

**Implications:**
- Only users in the dedicated `STAFF_GROUP` get pretix staff access.
- Removing a user from the Discourse group revokes pretix staff on their next login.
- Pretix `is_staff` set manually via pretix's admin UI will be overwritten on the next Discourse login. To grant staff access, add the user to the Discourse group.

#### Step 13: Team sync (within a database transaction)

All team membership changes happen inside `transaction.atomic()`:

**Important: Team is scoped per-organizer.** Pretix's `Team` model has a ForeignKey to `Organizer`. Team names are **not globally unique** — two organizers can have identically-named teams. All team queries **must** be scoped to the configured `ORGANIZER` (see [Section 4.4 Configuration](#44-configuration)):

```
Team.objects.filter(organizer=ORGANIZER, name__in=expected_team_names)
```

**Add to teams:**
- For each parsed city, compute the expected team name using `TEAM_TEMPLATE.format(city=city)`.
- Query pretix for teams matching those exact names **within the configured organizer**.
- Add the user to each found team (idempotent — `team.members` is a simple M2M; `add()` is safe to call repeatedly).
- Teams that don't exist in pretix are skipped with a **WARNING log** (not silently).

**Remove from stale teams:**
- Compute the "managed prefix" by splitting `TEAM_TEMPLATE` on `{city}` and taking the left side, stripped.
  - Example: `"Ansible Meetup Organisers - {city}"` → prefix `"Ansible Meetup Organisers -"`
- Find all teams the user belongs to **within the configured organizer** whose name starts with that prefix.
- Remove the user from any of those teams that are NOT in the expected set.

**Result:** On each login, the user's pretix team membership is made consistent with their current Discourse group membership, scoped to managed teams within the configured organizer.

#### Step 14: Login

- Call pretix's `process_login(request, user, keep_logged_in=False)`.
- Session is browser-scoped (expires on browser close).
- Post-login redirect: `process_login` calls `backend.get_next_url(request)` which uses `request.GET.get("next")`. Pretix validates this against `url_has_allowed_host_and_scheme(next_url, allowed_hosts=None)`, which restricts to the current host — **no open redirect risk** (verified in pretix source).

### 3.3 Backend Visibility

The "Log in with Discourse" button appears on pretix's login page **only if** all of the following are true:
- `DISCOURSE_URL` is configured (non-empty) and uses HTTPS (or `allow_http=true` for local dev).
- `DISCOURSE_SECRET` is configured (non-empty) and at least 32 characters.
- `API_KEY` is configured (non-empty).

If any condition is not met, the backend is invisible — pretix falls through to its other configured auth backends. This is the fail-secure posture: misconfiguration results in the plugin being **disabled**, not silently degraded.

### 3.4 Rejection Matrix

Every rejection scenario in the callback flow, consolidated in one table. All rejections redirect to the login page with the specified user-facing message. Log fields never include secrets, nonces, or full SSO payloads.

| ID | Step | Condition | User message | Log level | Log fields |
|----|------|-----------|-------------|-----------|------------|
| R1 | 1 | Missing `sso` or `sig` parameter | "Invalid response from Discourse." | WARNING | Client IP |
| R2 | 2 | HMAC signature mismatch | "Signature mismatch. Authentication failed." | WARNING | Client IP, truncated `sig` |
| R3 | 3 | Invalid base64 or UTF-8 in payload | "Could not decode Discourse response." | WARNING | Client IP |
| R4 | 3 | Payload contains `failed=true` | "Discourse authentication failed or was cancelled." | INFO | Client IP |
| R5a | 4 | Nonce missing from session (session expired or new browser) | "Session expired or invalid nonce. Please try again." | WARNING | Client IP, cause: "missing" |
| R5b | 4 | Nonce mismatch (possible replay or tampering) | "Session expired or invalid nonce. Please try again." | WARNING | Client IP, cause: "mismatch" |
| R5c | 4 | Nonce expired (age > 10 min) | "Session expired or invalid nonce. Please try again." | WARNING | Client IP, nonce age in seconds, max age |
| R6 | 5 | Missing `external_id` or `email` | "Incomplete identity data received." | WARNING | Client IP |
| R7 | 7 | Privileged user + `no_2fa_methods=true` | "Privileged account blocked: Please enable 2FA in your Discourse security settings." | WARNING | `external_id`, `username` |
| R8 | 8 | Email ends with `@anonymized.invalid` | "Account blocked: Anonymized account detected." | WARNING | `external_id` |
| R9 | 9 | Enrichment API error (any: network, timeout, non-200, invalid JSON) | "Could not verify security status with Discourse. Please try again later." | ERROR | Exception type, URL (no API key), HTTP status if available |
| R10 | 10 | User is silenced (`silenced_till` present and non-null) | "Account blocked: Moderation (silenced)." | WARNING | `external_id` |
| R11 | 10 | User is suspended (`suspended_till` present and non-null) | "Account blocked: Moderation (suspended)." | WARNING | `external_id` |
| R12 | 10 | Privileged + `second_factor_enabled=false` (enrichment layer) | "Privileged account blocked: Please enable 2FA in your Discourse security settings." | WARNING | `external_id` |
| R13 | 11 | `EmailAddressTakenError` during user provisioning | "Email conflict: Another user with this email exists. Please contact an administrator." | WARNING | `external_id`, email |
| R14 | 9 | API returns 401/403 (bad/revoked API key) | Same as R9 | **ERROR** | Additionally: "API key may be invalid or revoked" |

**Design principle:** Every rejection is logged. Every API/config error fails secure (denies access). There is no "silently continue with defaults" path — if a security check cannot be completed, access is denied.

---

## 4. Technical Architecture

### 4.1 System context

```
                                         ┌──────────────────────┐
                                         │  Discourse           │
                                         │  (forum.ansible.com) │
                                         │                      │
                                    SSO  │  /session/sso_provider│
    ┌────────────┐   redirect      ◄─────┤                      │
    │            │──────────────────►     │  /admin/users/:id    │
    │  Browser   │                       │  (Admin API)         │
    │            │◄──────────────────►    └──────────────────────┘
    └────────────┘   redirect            
         │                               
         │ HTTPS                         
         ▼                               
    ┌────────────────────────────────┐   
    │  Pretix                        │   
    │  ┌──────────────────────────┐  │   
    │  │ pretix-discourse-auth    │  │   
    │  │  - DiscourseAuthBackend  │  │   
    │  │  - return_view           │  │   
    │  └──────────────────────────┘  │   
    │  ┌──────────────────────────┐  │   
    │  │ Django ORM               │  │   
    │  │  - User                  │  │   
    │  │  - Team                  │  │   
    │  │  - Session               │  │   
    │  └──────────────────────────┘  │   
    └────────────────────────────────┘   
```

### 4.2 Tech stack

| Component           | Technology                     | Notes                                                    |
|---------------------|--------------------------------|----------------------------------------------------------|
| Runtime             | Python 3.9+                    | Match pretix's supported Python versions                 |
| Web framework       | Django (via pretix)            | Plugin does not choose the Django version; pretix does    |
| HTTP client         | `requests`                     | For Discourse Admin API calls                            |
| Cryptography        | Python stdlib `hmac`, `hashlib`, `secrets`, `base64` | No third-party crypto dependencies |
| Plugin framework    | pretix plugin system           | `BaseAuthBackend`, `pretix.cfg` config, entry points     |
| Build system        | setuptools + `pretix-plugin-build` | Via `pyproject.toml`                                 |

### 4.3 Plugin structure

```
pretix_discourse_auth/
    __init__.py          # Version, default_app_config
    apps.py              # Django AppConfig + PretixPluginMeta
    backend.py           # DiscourseAuthBackend (login initiation)
    views.py             # return_view (SSO callback + all business logic)
    urls.py              # Single route: _discourse/login/return/
    signals.py           # Empty (placeholder for future signal receivers)
    locale/              # i18n translation files (de, de_Informal)
    static/              # Empty (placeholder)
    templates/           # Empty (placeholder)
```

### 4.4 Configuration

All configuration is read from pretix's `pretix.cfg` file (INI format) under the `[discourse_auth]` section. Values are loaded once at module import time. Config changes require a process restart.

| Key                      | Required | Default              | Description                                      |
|--------------------------|----------|----------------------|--------------------------------------------------|
| `url`                    | Yes      | —                    | Discourse instance base URL. **Must be HTTPS** (unless `allow_http=true`). |
| `sso_secret`             | Yes      | —                    | Shared secret for DiscourseConnect HMAC signing. **Minimum 32 characters.** |
| `api_key`                | Yes      | —                    | Discourse Admin API key for enrichment. **Required** — without it, silenced/suspended checks cannot run and the backend refuses to register. |
| `api_username`           | No       | `system`             | Discourse username for API requests.             |
| `organizer`              | Yes      | —                    | Pretix organizer slug. Team queries are scoped to this organizer. Required because pretix Team names are not globally unique. |
| `host_prefix`            | No       | `meetup-host`        | Group name prefix identifying meetup hosts. **Must not be empty.** |
| `staff_group`            | No       | `meetup-admin`       | Discourse group name that grants pretix `is_staff` (exact match, case-insensitive). **Must not collide with Discourse automatic group names** (`staff`, `admins`, `moderators`, `trust_level_*`, `everyone`, etc.). |
| `team_template`          | No       | `Ansible Meetup Organisers - {city}` | Python format string. **Must contain `{city}`.** |
| `enforce_2fa_privileged` | No       | `true`               | Require 2FA for privileged users. Enforced at two layers: DiscourseConnect protocol (`require_2fa`) and enrichment API (`second_factor_enabled`). |
| `api_timeout`            | No       | `10`                 | Timeout in seconds for Discourse Admin API calls. |
| `allow_http`             | No       | `false`              | Allow non-HTTPS Discourse URL. **For local development only.** |

Example `pretix.cfg` section:

```ini
[discourse_auth]
url = https://forum.ansible.com
sso_secret = <shared-secret-from-discourse-admin-min-32-chars>
api_key = <discourse-admin-api-key>
api_username = system
organizer = ansible-meetups
host_prefix = meetup-host
staff_group = meetup-admin
team_template = Ansible Meetup Organisers - {city}
enforce_2fa_privileged = true
```

### 4.5 Data model

The plugin **does not define its own database models**. It operates on pretix's existing models:

| Model          | How used | Verified details |
|----------------|----------|------------------|
| `User`         | Created/updated via `get_or_create_for_backend()`. Fields: `email`, `fullname`, `is_staff` (boolean, grants site-wide admin access), auth backend linkage (`discourse` + `external_id`). | `is_staff` gates the `staff_member_required` decorator. `get_or_create_for_backend` always force-updates email (hardcoded in pretix). |
| `Team`         | Looked up by exact name **scoped to an organizer** (`ForeignKey` to `Organizer`). User added/removed via M2M `members` relation (simple M2M, no through table). Plugin never creates or deletes teams. | Team names are NOT globally unique. `members.add()` / `remove()` are idempotent. |
| `Organizer`    | Looked up by slug from config `organizer` key. Used to scope all Team queries. | |
| Django Session | Stores `discourse_sso_nonce` and `discourse_sso_nonce_created` for replay protection. | |

### 4.6 URL routing

| Method | Path                           | View           | Name     |
|--------|--------------------------------|----------------|----------|
| GET    | `/_discourse/login/return/`    | `return_view`  | `return` |

The URL is registered under the `plugins:pretix_discourse_auth` namespace.

### 4.7 External API calls

| Endpoint                                     | Method | Auth headers                          | When called    | Timeout |
|----------------------------------------------|--------|---------------------------------------|----------------|---------|
| `{DISCOURSE_URL}/session/sso_provider`       | GET    | None (HMAC in query params)           | Login initiation (browser redirect) | N/A |
| `{DISCOURSE_URL}/admin/users/{external_id}.json` | GET | `Api-Key`, `Api-Username`            | Every SSO callback | Configurable (`api_timeout`, default 10s) |

---

## 5. Non-Functional Requirements

These are requirements that the prototype either skipped entirely or handled minimally. The rebuild must address them.

### 5.1 Configuration validation

All validation runs at module import time. If any required check fails, the auth backend sets `visible = False` — it does not appear on the login page. This is the fail-secure posture: misconfiguration disables the plugin rather than degrading silently.

| Requirement | Behavior on failure |
|---|---|
| `url` must be HTTPS (or `allow_http=true`) | Backend invisible. Log ERROR: "Discourse URL must use HTTPS." |
| `sso_secret` must be ≥ 32 characters | Backend invisible. Log ERROR: "SSO secret too short (minimum 32 characters)." |
| `api_key` must be configured | Backend invisible. Log ERROR: "API key is required for security enrichment." |
| `organizer` must be configured and resolve to an existing Organizer | Backend invisible. Log ERROR: "Organizer '{slug}' not found." |
| `team_template` must contain `{city}` | Team sync disabled (login still works). Log ERROR: "team_template missing {city} placeholder — team sync disabled." |
| `host_prefix` must not be empty | Backend invisible. Log ERROR: "host_prefix must not be empty." |
| `staff_group` must not collide with Discourse automatic groups | Log WARNING: "staff_group '{name}' may collide with a Discourse automatic group." (Advisory — not blocking, because the admin may have intentionally chosen this name.) |

### 5.2 Logging

| Event                        | Level   | Required fields                                              |
|------------------------------|---------|--------------------------------------------------------------|
| Login initiated              | INFO    | Return URL                                                   |
| SSO callback received        | DEBUG   | (No PII — just "callback received")                         |
| Rejection (any R1-R14)       | Per [Rejection Matrix](#34-rejection-matrix) | Per matrix |
| Identity extracted           | INFO    | `external_id`, username, number of groups, is_staff (from group), is_privileged |
| Enrichment API call          | DEBUG   | URL (without API key), response status code                  |
| User provisioned (new)       | INFO    | `external_id`, email                                         |
| User updated (existing)      | DEBUG   | `external_id`, fields changed                                |
| `is_staff` changed           | WARNING | `external_id`, old value → new value, staff group name       |
| Team added                   | INFO    | `external_id`, team name                                     |
| Team removed                 | INFO    | `external_id`, team name                                     |
| Team not found               | WARNING | Expected team name, city                                     |
| Config validation             | ERROR or WARNING | Per [Section 5.1](#51-configuration-validation)         |

**PII handling:** Log `external_id` and `username` freely (they are public Discourse identifiers). Log `email` only on user creation. Never log the SSO payload, nonces, secrets, or API keys.

**Note:** Rejection logging details are defined in the [Rejection Matrix](#34-rejection-matrix) and are not duplicated here.

### 5.3 Testing

The rebuild must include:

**Unit tests (mocked external dependencies):**
- Signature verification: valid, tampered payload, tampered signature, empty, missing, trailing whitespace.
- Nonce: valid, missing from session, mismatched, already consumed (replay), expired (>10 min).
- Payload decoding: valid, invalid base64, invalid UTF-8, missing fields, `failed=true`.
- Group parsing: no groups, single host group, multiple host groups, non-host groups, prefix-only group (no city), multi-word city, mixed case, automatic Discourse groups (`trust_level_0`, `staff`, `everyone`).
- City normalization: `new-york` → `New York`, `berlin` → `Berlin`, `kuala-lumpur` → `Kuala Lumpur`.
- 2FA enforcement: `no_2fa_methods=true` for privileged, for unprivileged, missing field, enrichment-layer `second_factor_enabled` cross-check.
- RTBF detection: email ending with `@anonymized.invalid`, normal email, edge cases.
- Enrichment API: HTTP 200 with correct fields, 200 with missing fields, 401, 403, 500, timeout, invalid JSON.
- Enrichment field parsing: `silenced_till` present vs absent, `suspended_till` present vs absent, `second_factor_enabled` present vs absent.
- Policy enforcement: each condition independently, combined conditions, privileged vs non-privileged.
- Team sync: add to new team, idempotent re-add, remove from stale team, no matching teams, organizer scoping.
- `is_staff` sync: promotion via group membership, demotion via group removal, no change, user not in staff group.
- Email conflict handling.
- Config validation: each validation rule independently.

**Integration tests (with a real or stubbed Discourse):**
- Full round-trip: initiation → Discourse redirect → callback → logged in.
- Changed email between logins.
- Changed groups between logins.
- Concurrent logins (two tabs).

**Test framework:** `pytest` + `pytest-django` (matches pretix's own test setup). Use `responses` or `requests-mock` for HTTP mocking.

### 5.4 Rate limiting

- Rely on pretix's existing login rate limiting if available.
- If not, apply rate limiting on the callback endpoint: max 10 requests per IP per minute. Failed attempts (signature mismatch, nonce mismatch) should count double.

### 5.5 Internationalization

- Wrap all user-facing error messages in `gettext_lazy()` (`_(...)`).
- Provide English strings as the base.
- Include translation stubs for German (`de`) and informal German (`de_Informal`).

### 5.6 Dependency management

| Dependency    | Required action                     |
|---------------|-------------------------------------|
| `requests`    | Add to `pyproject.toml` `dependencies`. Even though pretix bundles it, an explicit declaration is correct. |
| `pretix`      | Do not add — it's the host application. Document the minimum supported pretix version. |

---

## 6. Assumptions and Edge Cases

### 6.1 Verified assumptions

These assumptions have been verified against Discourse and pretix source code.

| Assumption | Verification |
|---|---|
| **`external_id` in SSO provider mode is the Discourse user's internal database ID.** | Confirmed: `sso.external_id = current_user.id.to_s` in `discourse_connect_provider.rb:80`. |
| **`groups` payload is comma-separated group names.** | Confirmed: `current_user.groups.pluck(:name).join(",")` in `discourse_connect_provider.rb:83`. |
| **`groups` includes automatic Discourse groups.** | Confirmed: includes `trust_level_0`, `staff`, `everyone`, `admins`, etc. The `host_prefix` and `staff_group` filters must not collide with these names. |
| **Suspended users cannot complete SSO.** | Confirmed: `current_user` returns `nil` for suspended users in `default_current_user_provider.rb`. The SSO provider redirects to login — they never reach pretix. |
| **Silenced users CAN complete SSO.** | Confirmed: silencing restricts posting, not authentication. The enrichment API check for `silenced_till` is the only defense. |
| **Anonymized users cannot complete SSO.** | Confirmed: `UserAnonymizer` destroys `single_sign_on_record`, `oauth2_user_infos`, `user_associated_accounts`, `api_keys`, `user_auth_tokens`. The user cannot log in to Discourse at all. |
| **Anonymized email domain is `@anonymized.invalid`.** | Confirmed: `EMAIL_SUFFIX = "@anonymized.invalid"` in `user_anonymizer.rb:6`. |
| **Anonymized username pattern is `anon` + digits.** | Confirmed: `anon#{(SecureRandom.random_number * 100_000_000).to_i}` in `user_anonymizer.rb:108`. |
| **`team.members` is a simple M2M.** | Confirmed: `members = models.ManyToManyField(User, related_name="teams")` in pretix `organizer.py:377`. No through table. `add()`/`remove()` are idempotent. |
| **Team is scoped per-organizer, NOT globally unique by name.** | Confirmed: `Team` has `ForeignKey` to `Organizer`. No unique constraint on `name`. Two organizers can have identically-named teams. |
| **`get_or_create_for_backend` always force-updates email.** | Confirmed: `set_always.update({'email': email})` is hardcoded in pretix `auth.py:136`. Cannot be skipped by the caller. |
| **`is_staff` grants site-wide admin access.** | Confirmed: gates the `staff_member_required` decorator in pretix `permissions.py:153`. |
| **`process_login` validates `next` parameter.** | Confirmed: uses `url_has_allowed_host_and_scheme(next_url, allowed_hosts=None)` which restricts to the current host. No open redirect risk. |
| **`require_2fa=true` works in SSO provider mode.** | Confirmed: implemented in `discourse_connect_provider.rb`, called from `session_controller.rb:69`. Returns `no_2fa_methods=true` if user has no 2FA configured; does not block — consumer decides. |

### 6.2 Remaining assumptions (not yet verified)

| Assumption | Risk if wrong |
|---|---|
| **Pretix teams are pre-created manually by an admin.** The plugin never creates teams. | A new meetup city requires someone to manually create the pretix team. The plugin logs a WARNING when a city maps to a nonexistent team. |
| **`pretix.cfg` is the only config source.** Module-level `config.get()` reads from the INI file. | Environment variable overrides or secrets managers are not supported. |
| **One Discourse instance per pretix deployment.** Config is global. | Multi-tenant deployments are not supported (by design — see Q4). |
| **The `return_sso_url` in the SSO payload is trusted by Discourse.** | Discourse must be configured to accept redirects to the pretix domain. |

### 6.3 Edge cases

| Edge case | Behavior | Risk level |
|---|---|---|
| **User changes email in Discourse between logins.** | `get_or_create_for_backend` matches on `('discourse', external_id)`, not email. Email is force-updated. If the new email is already claimed by another pretix user, `EmailAddressTakenError` blocks login (R13). | MEDIUM — user is locked out until an admin resolves the conflict. Cannot be changed without patching pretix. |
| **User's display name is empty and username is also empty.** | `name` falls back to `username`, which is `''`. User is created with empty `fullname`. | LOW — cosmetic. |
| **Discourse returns duplicate group names.** | Groups are collected into a `set`; duplicates are eliminated. | NONE — handled. |
| **Two users log in simultaneously, both added to the same team.** | `team.members.add()` is idempotent. No conflict. | NONE — handled. |
| **`HOST_PREFIX` is set to empty string.** | Rejected at startup by config validation. | NONE — prevented. |
| **Discourse API returns 200 but `second_factor_enabled` key is missing.** | `api_data.get('second_factor_enabled')` returns `None` → `bool(None)` = `False`. Privileged user is blocked by 2FA check (fail-secure). | LOW — correct behavior (fail-secure). |
| **Discourse API returns 200 but `silenced_till` key is absent.** | `api_data.get('silenced_till')` returns `None` → `bool(None)` = `False`. User is not treated as silenced. | NONE — correct: key absence means user is not silenced. |
| **Team is renamed in pretix after user was added.** | On next login, old team name won't match expected; removal happens for the old name. The renamed team (no longer matching managed prefix) keeps the user as orphaned membership. | LOW — edge case during team administration. |
| **Team with same name exists in a different organizer.** | Team queries are scoped to the configured `organizer`. No cross-organizer match. | NONE — handled by organizer scoping. |
| **`staff_group` set to `staff` (Discourse automatic group).** | All Discourse staff (admins + moderators) would get pretix `is_staff`. Config validation logs a WARNING about collision with automatic groups. | MEDIUM — misconfiguration, but admin may intend it. |

### 6.4 Known limitations

#### 6.4.1 No session invalidation on status change

If a user is silenced in Discourse, their existing pretix sessions remain valid. The block only applies on next login attempt. A silenced user with an active session continues to have full access until the session expires.

**Future improvement:** On each enrichment check that detects silenced status, invalidate the user's active sessions via Django's session framework. Alternatively, implement a middleware that periodically re-checks status.

#### 6.4.2 Login-time-only sync

Group → team sync only happens at login. If a user is removed from a Discourse group, they retain pretix team membership until their next login.

**Future improvement:** Subscribe to Discourse webhook events for user/group changes, or implement a periodic sync management command.

#### 6.4.3 Email conflict requires admin intervention

When `get_or_create_for_backend` raises `EmailAddressTakenError`, the user is locked out. The email update is hardcoded in pretix and cannot be skipped by the plugin. Resolution requires an admin to either change the conflicting user's email in pretix or merge accounts.

---

## 7. Risks

### 7.1 Operational risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Discourse outage blocks all pretix logins | Medium | High — no organizer can log in | Both the SSO flow and the enrichment API depend on Discourse. Document this dependency. Consider a break-glass local admin account. |
| Discourse API key is rotated without updating pretix config | Medium | High — enrichment fails, all users fail-closed (R9) | Monitoring/alerting on enrichment API errors (R14 specifically). Document the key rotation procedure. |
| SSO secret mismatch after rotation | Low | High — all logins fail with signature mismatch (R2) | Coordinate secret rotation procedure. Consider supporting dual secrets during rotation. |
| Pretix team not created for a new city | High | Medium — host can log in but has no team/permissions | Plugin logs WARNING when a city maps to a nonexistent team. Document the operational procedure. |
| Config changes require process restart | Guaranteed | Low | Document clearly. |

### 7.2 Security risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| SSO payload logged in web server access logs (GET params contain PII) | High | Medium — email/username in access logs | Inherent to the DiscourseConnect protocol (GET-based). Configure web server to avoid logging query strings for the callback URL. Ensure log rotation and access controls. |
| Group name injection (attacker creates `meetup-host-*` group in Discourse) | Low | Medium — unauthorized team access in pretix | Discourse group creation must be restricted to admins. Document as an ops requirement. Future improvement: add optional `host_cities` allowlist config. |
| Silenced user accesses pretix between silencing and next login | Medium | Low — silenced users have limited Discourse permissions but may still have pretix team access | Acceptable given login-time-only sync. Future: session invalidation or webhook-driven sync. |

---

## 8. Design Decisions

All design decisions are resolved. No open questions remain.

### Q1: `is_staff` sync mechanism — DECIDED

**Decision:** Use a dedicated Discourse group (configurable as `staff_group`, default `meetup-admin`).

The Discourse `admin` flag is not used. Staff access is granted only to members of the dedicated group. This decouples Discourse forum administration from pretix infrastructure access. `is_staff` grants **site-wide admin access** across all organizers in pretix (verified in pretix source).

**Bootstrap procedure:** Before enabling the plugin, ensure at least one user is in the `meetup-admin` Discourse group. Alternatively, create an initial pretix superuser via `python manage.py createsuperuser` before switching to Discourse SSO. If no one is in the staff group, no one can access the pretix admin panel.

The `staff_group` Discourse group should be configured with visibility set to **"owners" or "members"** to avoid exposing the list of privileged users.

---

### Q2: API failure mode — DECIDED

**Decision:** Fail secure for all users (option a).

When the Discourse Admin API enrichment call fails for any reason (network error, timeout, non-200 HTTP status, invalid JSON), **reject the login for all users**. The enrichment checks (silenced, suspended, 2FA) are security controls — if they cannot be verified, access is denied.

**Rationale:** The "fail secure" principle takes precedence over availability. With `require_2fa` handled at the protocol layer (Step 7), the enrichment call's primary remaining purpose is the silenced/suspended check. A silenced user who gains pretix access during an API outage could access personal data (names, emails) of event attendees. This risk outweighs the inconvenience of temporary login unavailability during a Discourse API outage.

**Mitigation for availability:** Maintain a break-glass local admin account (created via `python manage.py createsuperuser`) that does not use Discourse SSO. This provides emergency access during Discourse outages.

---

### Q3: Team provisioning — DECIDED

**Decision:** Teams are pre-created manually by pretix administrators.

The plugin never creates or deletes teams. When a Discourse group maps to a city that has no corresponding pretix team, the plugin logs a WARNING and the user receives no team assignment for that city.

**Operational procedure for new cities:**
1. Create the Discourse group (e.g., `meetup-host-tokyo`).
2. Create the pretix team (e.g., `Ansible Meetup Organisers - Tokyo`) within the configured organizer and set its permissions.
3. Add users to the Discourse group — team membership syncs on their next login.

---

### Q4: Multi-tenancy — DECIDED

**Decision:** Single pretix instance, single Discourse instance.

All configuration is global in `pretix.cfg`. Team queries are scoped to a single configured organizer. Per-organizer configuration is out of scope.

---

### Q5: RTBF detection — DECIDED

**Decision:** Email-domain heuristic only, as defense-in-depth.

**Constant:** `RTBF_EMAIL_SUFFIX = "@anonymized.invalid"`

RTBF detection checks only whether the user's email ends with `@anonymized.invalid` — the email suffix Discourse assigns during anonymization (verified in source: `UserAnonymizer::EMAIL_SUFFIX`).

Username and display name heuristics are **not used** — they produce false positives for legitimate usernames (`anonym`, `anondale`, users named "Anonymous").

**Rationale:** Discourse's anonymization process destroys all auth records (SSO records, OAuth tokens, API keys, auth tokens — verified in `user_anonymizer.rb`). An anonymized user **cannot log in to Discourse** at all, which means they cannot complete the SSO flow. The email-domain check is therefore pure defense-in-depth — it catches the theoretically impossible case where an anonymized user somehow reaches pretix's callback. The single strongest signal (email domain) is sufficient for this purpose. Zero false positives for legitimate users.

---

## 9. Deployment Checklist (Human-in-the-Loop)

These items require human decisions or actions before the plugin can be deployed. They cannot be resolved by code alone.

### 9.1 Discourse configuration (forum admin must complete)

- [ ] **Enable DiscourseConnect Provider** in Discourse admin → Settings → Login. The site setting `enable_discourse_connect_provider` must be `true`.
- [ ] **Set the SSO secret** in Discourse to match the `sso_secret` in `pretix.cfg`. Minimum 32 characters, cryptographically random.
- [ ] **Create the `meetup-admin` group** (or whatever `staff_group` is configured to). Set visibility to "owners" or "members" to avoid exposing the list of privileged users.
- [ ] **Add initial staff users** to the `meetup-admin` group before enabling the plugin. Without this, no one can access the pretix admin panel after switching to Discourse SSO.
- [ ] **Restrict group creation** to Discourse admins. If non-admin users can create groups, they could create `meetup-host-*` groups and grant themselves pretix team membership.
- [ ] **Create `meetup-host-{city}` groups** for each city that needs a pretix team.
- [ ] **Generate a Discourse Admin API key** with "All Users" scope. Record it for `pretix.cfg`.
- [ ] **Verify `groups` is in the DiscourseConnect provider claims.** In Discourse admin → Settings → DiscourseConnect, check that `discourse_connect_provider_claims` includes `groups`. Without this, the SSO payload will not include group memberships and team sync will silently produce no matches.

### 9.2 Pretix configuration (pretix admin must complete)

- [ ] **Create a break-glass local admin account** via `python manage.py createsuperuser`. This provides emergency access if Discourse is unavailable.
- [ ] **Determine the organizer slug** — run `Organizer.objects.values_list('slug', flat=True)` in the pretix shell to list available organizers. Set this as `organizer` in `pretix.cfg`.
- [ ] **Create pretix teams** for each city, following the `team_template` pattern (e.g., `Ansible Meetup Organisers - Berlin`). Configure appropriate permissions on each team (which events they can manage, what actions they can take).
- [ ] **Configure `pretix.cfg`** with all required values. See [Appendix C](#appendix-c-config-quick-reference).
- [ ] **Restart pretix** after config changes (config is loaded at module import time).

### 9.3 Verification steps

- [ ] Confirm the "Log in with Discourse" button appears on the pretix login page. If it doesn't, check `pretix.log` for ERROR-level config validation messages.
- [ ] Test login with a user who is in the `meetup-admin` group — verify `is_staff` is set.
- [ ] Test login with a user who is in a `meetup-host-{city}` group — verify team membership.
- [ ] Test login with a user who has no host groups — verify no team assignment.
- [ ] Test login with a user who has 2FA disabled — verify they are blocked (if `enforce_2fa_privileged=true`).
- [ ] Verify the Discourse Admin API key works by checking for ERROR-level "API key may be invalid" messages in logs.

### 9.4 Web server configuration

- [ ] **Configure the web server to suppress query string logging** for the callback URL (`/_discourse/login/return/`). The `sso` GET parameter contains base64-encoded PII (email, username, group memberships). This is inherent to the DiscourseConnect protocol and cannot be changed.
- [ ] **Ensure HTTPS** is enforced for the pretix domain (TLS termination at the proxy/load balancer).

### 9.5 Open security considerations for operator review

These are security tradeoffs the operator should understand and accept:

1. **Fail-secure posture:** If the Discourse Admin API is unreachable (network issues, Discourse downtime, API key rotation), **all logins are blocked**. This is by design — security over availability. The break-glass local admin account provides emergency access. If this tradeoff is unacceptable, the code must be modified.

2. **`is_staff` exclusive ownership:** The plugin overwrites `is_staff` on every Discourse login based on `meetup-admin` group membership. Manual `is_staff` grants via pretix's admin UI will be reverted on the user's next login. Staff access must be managed through the Discourse group.

3. **Email conflict lockout:** If a user changes their Discourse email to one already claimed by another pretix user on a different auth backend, they are locked out (`EmailAddressTakenError`). This is a pretix limitation — the email update is hardcoded and cannot be skipped by the plugin. Resolution requires admin intervention.

4. **Login-time-only sync:** Team membership and staff status sync only at login. A user removed from a Discourse group retains pretix access until their session expires and they log in again. Future improvement: webhook-driven sync or session invalidation middleware.

5. **Silenced users with active sessions:** A user silenced in Discourse after their last pretix login retains their pretix session. The silenced check only runs during the enrichment call at login time. Same future improvement as item 4.

---

## Appendix A: DiscourseConnect Protocol Reference

This plugin implements the **consumer** side of the DiscourseConnect protocol. Discourse is the **provider** (identity provider). See [Section 1 (Terminology)](#1-terminology) for definitions.

**Protocol flow:**
1. The consumer (pretix) constructs a `nonce` + `return_sso_url` payload, base64-encodes it, HMAC-signs it, and redirects the user's browser to Discourse.
2. The provider (Discourse) authenticates the user, constructs a response payload with identity data, base64-encodes it, HMAC-signs it, and redirects the user's browser back to `return_sso_url`.
3. The consumer verifies the signature, decodes the payload, and extracts the identity.

**Request payload fields (consumer → provider):**

| Field | Description |
|-------|-------------|
| `nonce` | Single-use random token for replay protection |
| `return_sso_url` | Callback URL for Discourse to redirect to |
| `require_2fa` | If `true`, Discourse prompts the user for 2FA before redirecting back |

**Response payload fields (provider → consumer):**

| Field | Type | Description |
|-------|------|-------------|
| `nonce` | string | Echoed from request |
| `external_id` | string | Discourse internal user ID (`user.id`). Verified in source: `sso.external_id = current_user.id.to_s` |
| `email` | string | User's email |
| `username` | string | User's handle |
| `name` | string | Display name |
| `admin` | string | `"true"` if Discourse admin (not used by this plugin) |
| `moderator` | string | `"true"` if Discourse moderator |
| `groups` | string | Comma-separated group names. **Includes all groups** — custom groups AND automatic groups (`trust_level_0`, `staff`, `everyone`, etc.). Verified in source: `current_user.groups.pluck(:name).join(",")` |
| `confirmed_2fa` | string | `"true"` if user passed 2FA challenge (only present when `require_2fa=true` was sent) |
| `no_2fa_methods` | string | `"true"` if user has no 2FA methods configured (only present when `require_2fa=true` was sent) |
| `avatar_url` | string | CDN URL for avatar |

**Key protocol properties:**
- All data transits via browser redirects (GET parameters).
- Integrity is protected by HMAC-SHA256 with a pre-shared secret.
- Confidentiality depends on HTTPS — the payload is base64-encoded, **not encrypted**.
- Replay protection depends on the consumer implementing nonce verification.
- Discourse expires nonces after **30 minutes** on its side.

**Implementation note:** The `sso` query parameter value received by Django may contain a trailing newline. **Do not strip whitespace** from `request.GET.get('sso')` before HMAC computation — doing so breaks signature verification.

**References:**
- DiscourseConnect protocol: https://meta.discourse.org/t/discourseconnect-official-single-sign-on-for-discourse-sso/13045
- Discourse as provider: https://meta.discourse.org/t/use-discourse-as-an-identity-provider-sso-discourseconnect/32974

## Appendix B: Pretix Plugin System Reference

Verified against pretix source code.

**Registration:** Plugins are registered via `pyproject.toml` entry points under `pretix.plugin`. The entry point value points to the `PretixPluginMeta` class.

**Auth backends (`pretix.base.auth.BaseAuthBackend`):** Required overrides: `identifier` (property/string), `verbose_name` (property/string). Optional: `visible` (property, default `True`), `login_form_fields`, `form_authenticate`, `request_authenticate`, `authentication_url(request)` (returns redirect URL or `None`), `get_next_url(request)`.

**Config:** `pretix.settings.config` is a `ConfigParser` instance reading from `pretix.cfg`.

**User creation (`pretix.base.models.auth`):**
`User.objects.get_or_create_for_backend(backend, identifier, email, set_always={}, set_on_creation={})` — matches on `(backend, identifier)`. Always force-updates `email` via `set_always` (hardcoded at line 136). Raises `EmailAddressTakenError` if the new email collides with a user on a different backend.

**Team model (`pretix.base.models.organizer`):**
`Team` has a `ForeignKey` to `Organizer` (line 375). `name` is `CharField(max_length=190)` with **no uniqueness constraint**. `members = ManyToManyField(User, related_name="teams")` — simple M2M, no through table.

**Login (`pretix.control.views.auth`):**
`process_login(request, user, keep_logged_in=bool)` — establishes Django session. Redirects to `backend.get_next_url(request)`, which defaults to `request.GET.get("next")`, validated by `url_has_allowed_host_and_scheme(next_url, allowed_hosts=None)`.

**Staff access (`pretix.base.models.auth`):**
`is_staff = BooleanField(default=False, verbose_name='Is site admin')`. Gates `staff_member_required` decorator (line 153 in `permissions.py`). Grants access to site-wide admin views across all organizers.

## Appendix C: Config quick-reference

```ini
[discourse_auth]
# REQUIRED — backend will not appear on login page if any are missing
url = https://forum.ansible.com
sso_secret = <shared-secret-from-discourse-admin-minimum-32-chars>
api_key = <discourse-admin-api-key>
organizer = ansible-meetups

# OPTIONAL (defaults shown)
api_username = system
host_prefix = meetup-host
staff_group = meetup-admin
team_template = Ansible Meetup Organisers - {city}
enforce_2fa_privileged = true
api_timeout = 10
allow_http = false
```
