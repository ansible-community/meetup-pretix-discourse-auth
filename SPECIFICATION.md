# Technical Specification: pretix-discourse-auth

**Version:** 1.1  
**Date:** 2026-10-04  
**Status:** DRAFT — two open decisions remain: [Q2 (API failure mode)](#q2-open-what-should-happen-when-the-discourse-admin-api-is-unreachable) and [Q5 (RTBF detection)](#q5-open-how-should-rtbf-detection-work-in-production)  
**Audience:** Engineering team rebuilding from scratch  

---

## 1. Executive Summary

### What it does

A pretix plugin that replaces pretix's built-in username/password login for the **pretix control panel** (the admin/organizer interface) with Single Sign-On via a Discourse forum — specifically `forum.ansible.com`.

When an operator clicks "Log in with Discourse," they are redirected to Discourse, authenticate there, and are redirected back. The plugin then:

1. Verifies the cryptographic SSO payload.
2. Provisions or updates a pretix user account.
3. Enforces security policies (2FA requirements, moderation blocks, RTBF detection).
4. Syncs Discourse group memberships to pretix team assignments — mapping meetup host groups (e.g., `meetup-host-berlin`) to pretix teams (e.g., `Ansible Meetup Staff - Berlin`).

### Core value proposition

Ansible community meetup organizers manage events through pretix. Rather than maintaining separate credentials, they log in with the same Discourse identity they already use on `forum.ansible.com`. Their Discourse group memberships automatically determine which pretix teams (and therefore which events/organizers) they can manage — no manual pretix user administration needed.

### Trust model

Discourse is the **identity provider** and **source of truth** for:
- User identity (email, username, display name)
- Group memberships (which cities a host manages, and whether they hold pretix staff access)
- Moderation status (silenced, suspended)
- 2FA status

Pretix is the **relying party**. It trusts Discourse's assertions about users, subject to its own policy layer (e.g., requiring 2FA for privileged accounts). Pretix staff access is controlled by membership in a dedicated Discourse group (configurable, not the Discourse admin flag).

---

## 2. Core Workflows

### 2.1 Login Initiation (pretix → Discourse)

**Trigger:** User clicks the "Log in with Discourse" button on the pretix control panel login page.

**Steps:**

1. The plugin's auth backend generates a cryptographically random nonce (32 bytes, URL-safe base64).
2. The nonce is stored in the user's Django session under key `discourse_sso_nonce`.
3. A payload string is constructed: `nonce=<nonce>&return_sso_url=<callback_url>`.
4. The payload is base64-encoded.
5. An HMAC-SHA256 signature is computed over the base64 payload using the shared SSO secret.
6. The user's browser is redirected to `{DISCOURSE_URL}/session/sso_provider?sso={payload_b64}&sig={sig}`.

**Callback URL format:** `https://{pretix_host}/_discourse/login/return/` (resolved via Django's `reverse()` using the named URL `plugins:pretix_discourse_auth:return`).

### 2.2 SSO Callback (Discourse → pretix)

**Trigger:** Discourse redirects the user's browser back to pretix's callback URL with `?sso=...&sig=...` query parameters.

**Steps (executed sequentially — each failure aborts to login page with error message):**

#### Step 1: Parameter validation
- Verify both `sso` and `sig` GET parameters are present.

#### Step 2: Signature verification
- Compute HMAC-SHA256 over the raw `sso` parameter value using the shared secret.
- Compare against the provided `sig` using constant-time comparison (`hmac.compare_digest`).
- **Failure mode:** Reject with "Signature mismatch."

#### Step 3: Payload decoding
- Base64-decode the `sso` parameter.
- Parse as a URL query string into key-value pairs.
- If the payload contains `failed=true`, reject with "Authentication failed or was cancelled."

#### Step 4: Nonce verification (replay protection)
- Pop `discourse_sso_nonce` from the session (single-use: once popped, it cannot be reused).
- Compare the payload's `nonce` against the saved nonce using constant-time comparison.
- **Failure mode:** Reject with "Session expired or invalid nonce."

#### Step 5: Identity extraction
Extract from the decoded payload:

| Payload field  | Required | Processing                        | Maps to               |
|----------------|----------|-----------------------------------|-----------------------|
| `external_id`  | Yes      | Used as-is                        | Auth backend identifier |
| `email`        | Yes      | Lowercased                        | User email            |
| `username`     | No       | Lowercased                        | RTBF heuristic input  |
| `name`         | No       | Falls back to `username` if empty | User fullname         |
| `groups`       | No       | Comma-separated string → set      | Team sync + staff sync input |

The Discourse `admin` flag is **not used**. Staff status is determined by group membership (see Step 10).

If `external_id` or `email` is missing/empty, reject with "Incomplete identity data."

#### Step 6: Group parsing
- From the full set of Discourse groups, filter those whose lowercased name starts with `HOST_PREFIX` (default: `meetup-host`).
- For each matching group, extract the city portion: everything after the prefix and its separator hyphen.
- Groups that match the prefix exactly (no city suffix) are skipped with a log warning.
- The city slug is normalized: hyphens replaced with spaces, then title-cased.
  - Example: `meetup-host-new-york` → `New York`
  - Example: `meetup-host-berlin` → `Berlin`
  - Example: `meetup-host-kuala-lumpur` → `Kuala Lumpur`
- Check whether the user belongs to the `STAFF_GROUP` (configurable, default: `meetup-admin`). This is an exact match on the group name, case-insensitive.
- A user is considered **privileged** if they belong to the staff group OR any host group.

#### Step 7: Security enrichment (Discourse Admin API)

**Precondition:** Only runs if `API_KEY` is configured.

- Call `GET {DISCOURSE_URL}/admin/users/{external_id}.json` with headers `Api-Key` and `Api-Username`.
- Timeout: 10 seconds.
- On HTTP 200, extract:
  - `second_factor_enabled` → boolean
  - `silenced` → boolean
  - `suspended` → boolean
- **On network/timeout error:** Fail closed — reject all users (not just privileged) with "Could not verify security status."
- **On non-200 HTTP status:** Silently continue with defaults (all flags `False`).

**RTBF heuristic (runs regardless of API key):**
A user is flagged as RTBF (Right To Be Forgotten / anonymized) if any of:
- Email ends with `@example.invalid`
- Username starts with `anon`
- Display name (lowercased) equals `anonymous`

#### Step 8: Policy enforcement

Evaluated in order; first match blocks login:

| Condition                                          | Error message                         |
|----------------------------------------------------|---------------------------------------|
| User is silenced or suspended                      | "Account blocked: Moderation"         |
| User is flagged RTBF                               | "Account blocked: Anonymized/RTBF"    |
| `ENFORCE_2FA` + user is privileged + no 2FA        | "Please enable 2FA in Discourse"      |

#### Step 9: User provisioning

- Call pretix's `User.objects.get_or_create_for_backend('discourse', external_id, email, ...)`.
  - On every login: update `fullname` to the current Discourse display name.
  - On first creation: no additional fields set.
- **On `EmailAddressTakenError`:** Reject with "Email conflict: Another user claims this email."

#### Step 10: Staff flag sync (group-based)

- Determine whether the user should have pretix `is_staff` by checking membership in the configured `STAFF_GROUP` Discourse group (default: `meetup-admin`).
- If the user's current `is_staff` value does not match, update it.
- This is a **write-on-every-login** operation, not an event-driven sync.
- The Discourse `admin` flag is explicitly **not used** for this — it maps to Discourse forum administration, which is a different trust domain from pretix infrastructure access.

**Implications:**
- Only users in the dedicated `STAFF_GROUP` get pretix staff access.
- Removing a user from the Discourse group revokes pretix staff on their next login.
- Pretix `is_staff` set manually via pretix's admin UI will be overwritten on the next Discourse login. To grant staff access, add the user to the Discourse group.

#### Step 11: Team sync (within a database transaction)

All team membership changes happen inside `transaction.atomic()`:

**Add to teams:**
- For each parsed city, compute the expected team name using `TEAM_TEMPLATE.format(city=city)`.
- Query pretix for teams matching those exact names.
- Add the user to each found team (idempotent — `team.members.add()` is safe to call repeatedly).
- Teams that don't exist in pretix are silently skipped.

**Remove from stale teams:**
- Compute the "managed prefix" by splitting `TEAM_TEMPLATE` on `{city}` and taking the left side, stripped.
  - Example: `"Ansible Meetup Staff - {city}"` → prefix `"Ansible Meetup Staff -"`
- Find all teams the user belongs to whose name starts with that prefix.
- Remove the user from any of those teams that are NOT in the expected set.

**Result:** On each login, the user's pretix team membership is made consistent with their current Discourse group membership, scoped to teams matching the managed prefix.

#### Step 12: Login

- Call pretix's `process_login(request, user, keep_logged_in=False)`.
- Session is browser-scoped (expires on browser close).

### 2.3 Backend Visibility

The "Log in with Discourse" button appears on pretix's login page **only if** both `DISCOURSE_URL` and `DISCOURSE_SECRET` are configured (non-empty). Otherwise the backend is invisible — pretix falls through to its other configured auth backends.

---

## 3. Technical Architecture

### 3.1 System context

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

### 3.2 Tech stack

| Component           | Technology                     | Notes                                                    |
|---------------------|--------------------------------|----------------------------------------------------------|
| Runtime             | Python 3.9+                    | Match pretix's supported Python versions                 |
| Web framework       | Django (via pretix)            | Plugin does not choose the Django version; pretix does    |
| HTTP client         | `requests`                     | For Discourse Admin API calls                            |
| Cryptography        | Python stdlib `hmac`, `hashlib`, `secrets`, `base64` | No third-party crypto dependencies |
| Plugin framework    | pretix plugin system           | `BaseAuthBackend`, `pretix.cfg` config, entry points     |
| Build system        | setuptools + `pretix-plugin-build` | Via `pyproject.toml`                                 |

### 3.3 Plugin structure

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

### 3.4 Configuration

All configuration is read from pretix's `pretix.cfg` file (INI format) under the `[discourse_auth]` section. Values are loaded once at module import time.

| Key                      | Required | Default              | Description                                      |
|--------------------------|----------|----------------------|--------------------------------------------------|
| `url`                    | Yes      | `''`                 | Discourse instance base URL (must be HTTPS)      |
| `sso_secret`             | Yes      | `''`                 | Shared secret for DiscourseConnect HMAC signing  |
| `api_key`                | No*      | `''`                 | Discourse Admin API key for enrichment           |
| `api_username`           | No       | `system`             | Discourse username for API requests              |
| `host_prefix`            | No       | `meetup-host`        | Group name prefix identifying meetup hosts       |
| `staff_group`            | No       | `meetup-admin`       | Discourse group name that grants pretix `is_staff` (exact match, case-insensitive) |
| `team_template`          | No       | `Ansible Meetup Staff - {city}` | Python format string; `{city}` is required |
| `enforce_2fa_privileged` | No       | `true`               | Require 2FA for staff/host users                 |

\* `api_key` is technically optional, but without it all security enrichment (2FA, suspension, RTBF API checks) is disabled. A startup warning is logged when `enforce_2fa_privileged` is `true` and `api_key` is missing.

Example `pretix.cfg` section:

```ini
[discourse_auth]
url = https://forum.ansible.com
sso_secret = <shared-secret-from-discourse-admin>
api_key = <discourse-admin-api-key>
api_username = system
host_prefix = meetup-host
staff_group = meetup-admin
team_template = Ansible Meetup Staff - {city}
enforce_2fa_privileged = true
```

### 3.5 Data model

The plugin **does not define its own database models**. It operates on pretix's existing models:

| Model          | How used                                                       |
|----------------|----------------------------------------------------------------|
| `User`         | Created/updated via `get_or_create_for_backend()`. Fields: `email`, `fullname`, `is_staff`, auth backend linkage (`discourse` + `external_id`). |
| `Team`         | Looked up by exact name. User added/removed via M2M `members` relation. Plugin never creates or deletes teams. |
| Django Session | Stores `discourse_sso_nonce` for replay protection.            |

### 3.6 URL routing

| Method | Path                           | View           | Name     |
|--------|--------------------------------|----------------|----------|
| GET    | `/_discourse/login/return/`    | `return_view`  | `return` |

The URL is registered under the `plugins:pretix_discourse_auth` namespace.

### 3.7 External API calls

| Endpoint                                     | Method | Auth headers                          | When called    | Timeout |
|----------------------------------------------|--------|---------------------------------------|----------------|---------|
| `{DISCOURSE_URL}/session/sso_provider`       | GET    | None (HMAC in query params)           | Login initiation (browser redirect) | N/A |
| `{DISCOURSE_URL}/admin/users/{external_id}.json` | GET | `Api-Key`, `Api-Username`            | Every SSO callback (if `api_key` configured) | 10s |

---

## 4. Non-Functional Requirements

These are requirements that the prototype either skipped entirely or handled minimally. The rebuild must address them.

### 4.1 Configuration validation

| Requirement | Prototype behavior | Required behavior |
|---|---|---|
| `url` must be HTTPS | Logs a warning | **MUST** refuse to register the auth backend (make it invisible) if URL is not HTTPS in production. Allow HTTP only if a `DEBUG`/`allow_http` flag is explicitly set, for local development. |
| `team_template` must contain `{city}` | No validation | Validate at startup. If missing, log an error and disable team sync (but allow login). |
| `sso_secret` minimum length | No validation | Reject secrets shorter than 32 characters at startup with a clear error. |
| `api_key` presence vs. `enforce_2fa` | Logs a warning | Log at WARNING level at minimum. Consider refusing to start if `enforce_2fa_privileged=true` without an `api_key`. |

### 4.2 Logging

The prototype logs team sync operations at INFO level. The rebuild must implement structured logging:

| Event                        | Level   | Required fields                                              |
|------------------------------|---------|--------------------------------------------------------------|
| Login initiated              | INFO    | Discourse username (if available from session), return URL   |
| SSO callback received        | DEBUG   | (No PII — just "callback received")                         |
| Signature mismatch           | WARNING | Client IP, truncated `sig` value                             |
| Nonce mismatch/expired       | WARNING | Client IP                                                    |
| Identity extracted           | INFO    | `external_id`, username, number of groups, is_staff (from group), is_privileged |
| Enrichment API call          | DEBUG   | URL (without API key), response status code                  |
| Enrichment API failure       | ERROR   | Exception type, URL                                          |
| Policy block                 | WARNING | `external_id`, block reason (silenced/suspended/RTBF/2FA)   |
| User provisioned (new)       | INFO    | `external_id`, email                                         |
| User updated (existing)      | DEBUG   | `external_id`, fields changed                                |
| `is_staff` changed           | WARNING | `external_id`, old value → new value, staff group name       |
| Team added                   | INFO    | `external_id`, team name                                     |
| Team removed                 | INFO    | `external_id`, team name                                     |
| Team not found               | WARNING | Expected team name, city                                     |
| Config validation warning    | WARNING | Specific issue                                               |

**PII handling:** Log `external_id` and `username` freely (they are public Discourse identifiers). Log `email` only on user creation. Never log the SSO payload, nonces, secrets, or API keys.

### 4.3 Error handling

| Failure scenario                     | Prototype behavior              | Required behavior                                                |
|--------------------------------------|---------------------------------|------------------------------------------------------------------|
| Discourse Admin API returns non-200  | Silently continues with defaults | Log at WARNING. If status is 401/403, log at ERROR ("API key may be invalid/revoked"). |
| Discourse Admin API returns invalid JSON | Unhandled exception (500)    | Catch `JSONDecodeError`, log at ERROR, fail closed (same as network error). |
| `resp.json()` called twice           | Double parse                    | Parse once, store in local variable.                             |
| `User.objects.get_or_create_for_backend` unexpected error | Unhandled (500) | Catch broad exceptions, log at ERROR, redirect to login with generic error. |
| Team sync DB error                   | `transaction.atomic()` rolls back | Correct — keep this behavior. Additionally log the exception at ERROR. |
| Discourse URL is unreachable entirely | Timeout after 10s, fail closed | Correct — keep this behavior. Consider making timeout configurable. |

### 4.4 Testing

The prototype has zero meaningful tests. The rebuild must include:

**Unit tests (mocked external dependencies):**
- Signature verification: valid, tampered payload, tampered signature, empty, missing.
- Nonce: valid, missing from session, mismatched, already consumed (replay).
- Payload decoding: valid, invalid base64, invalid UTF-8, missing fields, `failed=true`.
- Group parsing: no groups, single host group, multiple host groups, non-host groups, prefix-only group (no city), multi-word city, mixed case.
- City normalization: `new-york` → `New York`, `berlin` → `Berlin`, `kuala-lumpur` → `Kuala Lumpur`.
- Policy enforcement: each condition independently, combined conditions, privileged vs non-privileged.
- RTBF heuristic: each pattern, false positives to document.
- Team sync: add to new team, idempotent re-add, remove from stale team, no matching teams, team template without `{city}`.
- `is_staff` sync: promotion via group membership, demotion via group removal, no change, user not in staff group.
- Email conflict handling.

**Integration tests (with a real or stubbed Discourse):**
- Full round-trip: initiation → Discourse redirect → callback → logged in.
- Changed email between logins.
- Changed groups between logins.
- Concurrent logins (two tabs).

**Test framework:** `pytest` + `pytest-django` (matches pretix's own test setup). Use `responses` or `requests-mock` for HTTP mocking.

### 4.5 Rate limiting

The prototype has no rate limiting. The rebuild should:
- Rely on pretix's existing login rate limiting if available.
- If not, apply rate limiting on the callback endpoint: max 10 requests per IP per minute. Failed attempts (signature mismatch, nonce mismatch) should count double.

### 4.6 Internationalization

The prototype wraps user-facing error messages in `gettext_lazy()` (`_(...)`). The rebuild must:
- Maintain this pattern for all user-facing strings.
- Provide English strings as the base.
- Include translation stubs for German (`de`) and informal German (`de_Informal`) — these directories exist in the prototype.

### 4.7 Dependency management

| Dependency    | Prototype declares it? | Required action                     |
|---------------|------------------------|-------------------------------------|
| `requests`    | No                     | Add to `pyproject.toml` `dependencies`. Even though pretix bundles it, an explicit declaration is correct. |
| `pretix`      | No (it's the host)     | Do not add — it's the host application. Document the minimum supported pretix version. |

---

## 5. Implicit Assumptions and Edge Cases

### 5.1 Assumptions the prototype makes

| Assumption | Risk if wrong |
|---|---|
| **Discourse's `external_id` in SSO provider mode is the Discourse user's internal database ID.** The Admin API endpoint uses this to look up user details. | If Discourse returns a different kind of ID (e.g., a UUID or the SSO provider's own external ID), the Admin API lookup will fail with 404, and enrichment silently produces defaults. |
| **Discourse groups are comma-separated in the `groups` SSO payload field.** | If Discourse changes the separator or encoding, all group parsing breaks silently — users get no team assignments. |
| **Pretix teams are pre-created manually by an admin.** The plugin never creates teams; it only adds/removes members. This is by design — teams require permission configuration that cannot be inferred from Discourse groups. | A new meetup city requires someone to manually create the pretix team before SSO team sync works. The plugin MUST log a WARNING when a city maps to a nonexistent team so operators know when provisioning is out of sync. |
| **`pretix.cfg` is the only config source.** Module-level `config.get()` reads from the INI file. | Environment variable overrides, secrets managers, or per-organizer settings are not supported. |
| **One Discourse instance per pretix deployment.** Config is global, not per-organizer or per-event. This is by design (see [Q4](#q4-multi-tenancy--decided)). | Multi-tenant pretix deployments where different organizers use different Discourse instances are not supported. |
| **`User.objects.get_or_create_for_backend` handles the `discourse`/`external_id` linkage internally.** | The plugin depends on pretix's undocumented internal API for backend-linked user creation. If pretix changes this API, the plugin breaks. |
| **The `return_sso_url` in the SSO payload is trusted by Discourse.** Discourse must be configured to accept redirects to the pretix domain. | If Discourse's allowed redirect URLs are misconfigured, the SSO flow will fail at the Discourse end. |
| **`team.members` is a Django M2M relation.** `add()` and `remove()` are idempotent. | If pretix changes the Team membership model (e.g., to a through table with additional fields), `add()`/`remove()` may not work. |

### 5.2 Edge cases

| Edge case | Current behavior | Risk level |
|---|---|---|
| **User changes email in Discourse between logins.** | `get_or_create_for_backend` matches on `('discourse', external_id)`, not email. The email is updated. If the new email is already claimed by another pretix user, `EmailAddressTakenError` blocks login. | MEDIUM — user is locked out with a confusing error until the email conflict is resolved manually. |
| **User changes username in Discourse to start with `anon`.** | RTBF heuristic triggers, user is blocked from pretix. | HIGH — false positive locks out a legitimate user. See [Q5 (OPEN)](#q5-open-how-should-rtbf-detection-work-in-production) for resolution options. |
| **User's display name is empty and username is also empty.** | `name` falls back to `username`, which is `''`. User is created with empty `fullname`. | LOW — cosmetic issue. |
| **Discourse returns duplicate group names.** | Groups are collected into a `set`, so duplicates are eliminated. | NONE — handled. |
| **Two users log in simultaneously and both should be added to the same team.** | Both `team.members.add()` calls are idempotent. No conflict. | NONE — handled by M2M `add()`. |
| **`TEAM_TEMPLATE` contains characters that are special in `startswith`.** | `startswith` is a literal string match, not a regex. Safe. | NONE. |
| **`HOST_PREFIX` is set to an empty string.** | Every group matches. All groups are treated as host groups with the full group name as the city slug. | MEDIUM — accidental misconfiguration produces nonsensical team names. |
| **Discourse API returns 200 but with unexpected JSON structure (no `second_factor_enabled` key).** | `api_data.get('second_factor_enabled')` returns `None`, `bool(None)` is `False`. User appears to not have 2FA. If privileged + `ENFORCE_2FA`, they're blocked. | MEDIUM — silent degradation. The API response schema is not validated. |
| **User is added to a pretix team, then the team is renamed.** | On next login, the old team name won't match the expected name, so removal happens. The renamed team (now not matching the managed prefix) is not touched — user stays in it as an orphaned membership. | LOW — edge case during team administration. |
| **`process_login` raises an exception.** | Unhandled — returns a 500. | LOW — pretix's own code; unlikely to fail. |

### 5.3 Known design issues

#### 5.3.1 `is_staff` via dedicated group (RESOLVED)

**Prototype issue:** The prototype mapped `Discourse admin == pretix is_staff`, creating cross-domain privilege escalation.

**Decision:** The rebuild uses a dedicated Discourse group (`staff_group`, default `meetup-admin`) instead of the Discourse `admin` flag. This decouples forum administration from pretix infrastructure access.

**Remaining risk:** Manual `is_staff` grants in pretix are still overwritten on next Discourse login. The plugin assumes exclusive ownership of `is_staff` for Discourse-authenticated users. This is intentional — staff access is managed through the Discourse group, not through pretix's admin UI. Document this clearly for operators.

#### 5.3.2 No session invalidation on status change

If a user is suspended in Discourse, their existing pretix sessions remain valid. The block only applies on next login attempt. A suspended user with an active session continues to have full access.

**Recommendation for rebuild:** On each enrichment check that detects silenced/suspended, call `django.contrib.sessions.models.Session.objects.filter(...)` to delete the user's active sessions. Alternatively, implement a middleware that re-checks status periodically.

#### 5.3.3 Login-time-only sync

Group → team sync only happens at login. If a user is removed from a Discourse group, they retain pretix team membership until their next login — which could be never if they have an active long-lived session.

**Recommendation for rebuild:** Consider a webhook receiver for Discourse group change events, or a periodic sync job.

---

## 6. Risks

### 6.1 Operational risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Discourse outage blocks all pretix logins | Medium | High — no organizer can log in | Implement a fallback auth mechanism or cached authorization window |
| Discourse API key is rotated without updating pretix config | Medium | High — enrichment fails, all users fail-closed | Monitoring/alerting on enrichment API errors. Document the key rotation procedure. |
| SSO secret mismatch after rotation | Low | High — all logins fail with signature mismatch | Coordinate secret rotation procedure. Consider supporting dual secrets during rotation. |
| Pretix team not created for a new city | High | Medium — host can log in but has no team/permissions | Log a WARNING when a city maps to a nonexistent team. Teams are pre-created by design — document the operational procedure (see [Q3](#q3-team-provisioning--decided)). |
| Module-level config never refreshes | Guaranteed | Low (until it matters) | Document that config changes require process restart. Consider lazy config loading. |

### 6.2 Security risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| SSO payload logged in web server access logs (GET params contain PII) | High | Medium — email/username in access logs | Documented tradeoff of Discourse's SSO protocol. Ensure log rotation and access controls. |
| RTBF false positive blocks legitimate user | Medium | Medium — user locked out, needs admin intervention | See [Q5 (OPEN)](#q5-open-how-should-rtbf-detection-work-in-production) for resolution options. |
| Group name injection (attacker creates `meetup-host-*` group in Discourse) | Low | Medium — unauthorized team access in pretix | Depends on Discourse group creation being restricted to admins. Document this as a Discourse configuration requirement. |
| No HTTPS enforcement | Low (if ops is careful) | Critical if exploited — secret/API key interception | Enforce HTTPS in code, not just warnings. |

---

## 7. Design Decisions

### Q1: `is_staff` sync mechanism — DECIDED

**Decision:** Use a dedicated Discourse group (configurable as `staff_group`, default `meetup-admin`).

The Discourse `admin` flag is not used. Staff access is granted only to members of the dedicated group. This decouples Discourse forum administration from pretix infrastructure access, eliminating the cross-domain privilege escalation risk from the prototype.

See [Step 10](#step-10-staff-flag-sync-group-based) and the `staff_group` config key in [Section 3.4](#34-configuration).

---

### Q2 (OPEN): What should happen when the Discourse Admin API is unreachable?

The Admin API enrichment call (2FA, suspension, RTBF checks) can fail due to network issues, Discourse downtime, or API key problems. The failure mode determines the availability vs. security tradeoff.

**Context:** The SSO redirect itself (browser-based) does not depend on the Admin API — users can still authenticate via Discourse. This question only affects the **server-to-server enrichment call** made during the callback.

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **(a) Fail closed for everyone** | If the API call fails, reject all logins regardless of privilege level. (Prototype behavior.) | Simplest to implement. No security gap — suspended/silenced users cannot sneak through during an outage. Consistent behavior — users never see different outcomes for the same action. | A Discourse API outage (or misconfigured API key) blocks ALL pretix logins. No organizer can manage events. The blast radius is maximum — a monitoring gap in one system takes down another. |
| **(b) Fail closed for privileged users only** | If the API call fails, block staff/host users but allow unprivileged users through with default values (no 2FA required, not suspended, not silenced). | Reduces blast radius — regular attendee-facing operations continue during Discourse API outages. Privileged accounts (higher-value targets) remain protected. | Suspended/silenced unprivileged users can log in during an outage. Adds branching complexity — two code paths based on privilege. Privilege determination itself depends on group parsing, which comes from the SSO payload (not the API), so this is reliable. |
| **(c) Cache last-known-good enrichment** | On successful API calls, cache the enrichment result per user (keyed by `external_id`) with a configurable TTL (e.g., 1 hour). On API failure, use the cached result if fresh enough; reject if stale or missing. | Best availability — only truly new users or users with expired caches are blocked. Handles transient outages gracefully. Most API calls are redundant (same user logging in again) — cache eliminates unnecessary load. | Requires a cache backend (Django cache framework, Redis, or DB table). Cached "not suspended" can be stale — a user suspended 5 minutes ago may still log in if the cache TTL hasn't expired. Introduces state that can drift. More complex to test and reason about. |
| **(d) Non-blocking / log-only** | Make the enrichment call, but on failure, log a WARNING and allow the login to proceed with default values. | Maximum availability — Discourse API status never blocks pretix logins. Simple to implement. | All security enrichment becomes advisory, not enforcing. Suspended users can log in whenever the API is down (intentional or otherwise). An attacker who can cause API failures (e.g., by overwhelming Discourse) can bypass policy enforcement. Effectively makes the API key optional at runtime, even when configured. |

**Recommendation:** Option **(b)** balances security and availability. The highest-value accounts (staff, hosts with event management permissions) remain protected, while a Discourse API issue doesn't prevent all logins. The enrichment data matters most for privileged users — an unprivileged user who is suspended in Discourse has no destructive capabilities in pretix anyway.

**Decision required before implementation.**

---

### Q3: Team provisioning — DECIDED

**Decision:** Teams are pre-created manually by pretix administrators.

The plugin never creates or deletes teams. When a Discourse group maps to a city that has no corresponding pretix team, the user silently receives no team assignment for that city. This is by design — teams require permission configuration (which events they can manage, what actions they can take) that cannot be inferred from a Discourse group name alone.

**Required behavior in rebuild:** Log a WARNING when a city derived from a Discourse group has no matching pretix team. This gives operators visibility into provisioning gaps without requiring automatic team creation.

**Operational procedure for new cities:**
1. Create the Discourse group (e.g., `meetup-host-tokyo`).
2. Create the pretix team (e.g., `Ansible Meetup Staff - Tokyo`) and configure its permissions.
3. Add users to the Discourse group — team membership syncs on their next login.

---

### Q4: Multi-tenancy — DECIDED

**Decision:** Single pretix instance, single Discourse instance.

All configuration is global in `pretix.cfg`. All organizers share one Discourse instance, one SSO secret, one team template pattern. Per-organizer configuration is out of scope.

**Implication:** The config model remains simple (INI file, module-level loading). If multi-tenancy is needed in the future, it would require migrating config to pretix's per-organizer settings framework — a significant refactor affecting every module.

---

### Q5 (OPEN): How should RTBF detection work in production?

When a Discourse user exercises their Right To Be Forgotten, Discourse anonymizes their account: replaces the email with `@example.invalid`, changes the username to `anonNNNNN`, and clears the display name. The plugin should detect this and block login, because an anonymized user's identity data is no longer meaningful and they should not hold pretix access.

The prototype uses a pattern-matching heuristic that produces false positives (e.g., a user named `anondale` or someone who chose "Anonymous" as their display name).

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **(a) Tightened heuristic** | Keep pattern matching but use Discourse's exact anonymization patterns: email ends with `@example.invalid` (keep), username matches regex `^anon[0-9]+$` (tighten from prefix match), display name equals `"Anonymous"` (keep). Any one match triggers the block. | No API dependency — works even without `api_key`. Simple to implement. Catches the common case reliably. | Still possible (though unlikely) false positives: a user whose email domain is literally `example.invalid`, or who chose a purely numeric-suffixed `anon` username. Cannot detect partial anonymizations or custom anonymization patterns. Heuristic will break if Discourse changes its anonymization format. |
| **(b) API-based detection only** | Check the Discourse Admin API response for an explicit anonymization indicator. Discourse's `/admin/users/{id}.json` response may include fields indicating the account is anonymized (e.g., checking for `anonymized` or `staged` flags, or verifying the email matches `@anonymized.invalid`). | Authoritative — uses Discourse's own data rather than guessing patterns. No false positives for legitimate usernames. Future-proof against anonymization format changes. | Requires `api_key` — without it, no RTBF detection at all. Adds a hard dependency on the API for a safety-critical check. The exact API field for anonymization status needs to be verified against Discourse's current API documentation — it may not be a first-class field. |
| **(c) Remove RTBF detection entirely** | Do not check for anonymized accounts in the plugin. Rely on Discourse's own behavior: anonymized users have their email changed to `@example.invalid`, which means Discourse's SSO provider won't issue a valid SSO assertion for them (they can't log in to Discourse, so they can't complete the SSO flow). | Simplest — zero code, zero false positives, zero maintenance. Defense in depth at the Discourse layer rather than duplicating it. | If Discourse's anonymization is incomplete or misconfigured (e.g., the user can still log in via an alternative auth method), pretix has no backstop. Leaves an orphaned pretix user with stale team memberships — no cleanup path. If Discourse changes anonymization behavior, the assumption may silently break. |
| **(d) Combined: API primary, heuristic fallback** | If the API is available, check the API response for an anonymization indicator. If the API is unavailable or has no such field, fall back to the tightened heuristic (option a). | Best coverage — uses the authoritative source when available, degrades gracefully. Handles both "API key configured" and "API key not configured" deployments. | Most complex to implement and test. Two code paths for the same check. The fallback heuristic has the same (reduced) false positive risk as option (a). May give different results depending on API availability, making behavior harder to predict. |

**Recommendation:** Option **(c)** is the simplest and relies on the correct trust boundary — Discourse controls identity, and an anonymized Discourse user cannot complete SSO authentication. However, if defense-in-depth is valued, option **(a)** with the tightened regex (`^anon[0-9]+$`) eliminates the prototype's false positive problem while keeping a safety net.

**Decision required before implementation.**

---

## Appendix A: Discourse SSO (DiscourseConnect) Protocol Reference

The plugin implements the **provider** side of DiscourseConnect, where Discourse is the identity provider.

**Protocol flow:**
1. Consumer (pretix) constructs `nonce` + `return_sso_url`, base64-encodes, HMAC-signs, and redirects user to Discourse.
2. Discourse authenticates the user, constructs a response payload with identity data, base64-encodes, HMAC-signs, and redirects user back to `return_sso_url`.
3. Consumer verifies signature, decodes payload, extracts identity.

**Payload fields returned by Discourse:**
`nonce`, `external_id`, `email`, `username`, `name`, `admin`, `moderator`, `groups`, `avatar_url`, `profile_background_url`, `card_background_url`, and others.

**Key protocol properties:**
- All data transits via browser redirects (GET parameters).
- Integrity is protected by HMAC-SHA256 with a pre-shared secret.
- Confidentiality depends on HTTPS — the payload is base64-encoded, not encrypted.
- Replay protection depends on the consumer implementing nonce verification.

**Reference:** https://meta.discourse.org/t/discourseconnect-official-single-sign-on-for-discourse-sso/13045

## Appendix B: Pretix Plugin System Reference

**Registration:** Plugins are registered via `pyproject.toml` entry points under `pretix.plugin`. The entry point value points to the `PretixPluginMeta` class.

**Auth backends:** Subclass `pretix.base.auth.BaseAuthBackend`. Must define `identifier` (string), `verbose_name` (display string), `visible` (property), and `authentication_url(request)` (returns redirect URL or `None`).

**Config:** `pretix.settings.config` is a `ConfigParser` instance reading from `pretix.cfg`.

**User creation:** `User.objects.get_or_create_for_backend(backend_id, external_id, email, set_always={}, set_on_creation={})` handles the linkage between external identity and pretix user.

**Login:** `pretix.control.views.auth.process_login(request, user, keep_logged_in=bool)` establishes the Django session.

## Appendix C: Config quick-reference

```ini
[discourse_auth]
# REQUIRED
url = https://forum.ansible.com
sso_secret = <minimum 32 characters>

# RECOMMENDED (enables security enrichment)
api_key = <discourse-admin-api-key>
api_username = system

# OPTIONAL (defaults shown)
host_prefix = meetup-host
staff_group = meetup-admin
team_template = Ansible Meetup Staff - {city}
enforce_2fa_privileged = true
```
