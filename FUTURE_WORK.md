# Future Work

## Security Hardening

### Decouple `is_staff` from Discourse admin status
The current `is_staff` sync creates cross-domain privilege escalation. Replace with a dedicated config option (`staff_groups`) that maps specific Discourse groups to pretix staff, or remove `is_staff` sync entirely and manage it through pretix's admin UI. At minimum, make it opt-in rather than automatic.

### Validate HTTPS on Discourse URL
Refuse to start (or log a loud warning) if `DISCOURSE_URL` does not use `https://`. The SSO secret, API key, and user PII transit to this URL.

### Add nonce expiration
Store a timestamp alongside the nonce in the session and reject nonces older than a configurable window (e.g., 5 minutes). Prevents replay of captured SSO URLs from long-lived sessions.

### Warn on missing API key
If `API_KEY` is not configured, log a startup warning making it clear that 2FA enforcement, suspension checks, and RTBF detection are all disabled. Consider requiring it when `ENFORCE_2FA` is enabled.

### Wrap team sync in a database transaction
Use `django.db.transaction.atomic()` around the team add/remove block to prevent partial membership states on database errors.

### Active session invalidation
When the enrichment API detects a user is silenced/suspended, invalidate their existing pretix sessions (via Django's session framework) rather than only blocking new logins.

## Robustness

### Improve city name parsing
The current `split('-', 2)[-1].title()` approach breaks for multi-word cities (hyphens preserved), no-city groups (yields `host`), and cities with special characters. Consider:
- Using a dedicated separator (e.g., `meetup-host--new-york` with double-hyphen)
- Storing a group-to-city mapping in config
- Fetching group metadata from the Discourse API for a display name

### Tighten RTBF heuristic
The `username.startswith('anon')` check produces false positives for legitimate usernames. Use the Discourse API's anonymization metadata instead, or check for the exact `anonNNNNNN` pattern Discourse generates.

### Log missing teams
When a Discourse group maps to a city but no corresponding pretix team exists, log a warning (not just the empty "Found in Pretix DB" list). Operators need to know when team provisioning is out of sync.

### Handle `TEAM_TEMPLATE` without `{city}`
Validate at startup that `TEAM_TEMPLATE` contains `{city}`. Without it, the prefix extraction and team matching logic produces undefined behavior.

## Features

### Per-team permission mapping
Map Discourse groups to specific pretix team permissions (e.g., `meetup-host-*` gets `can_change_orders`, `meetup-checkin-*` gets `can_checkin`). Currently all team members inherit whatever the team's existing permissions are, with no SSO-driven granularity.

### "Remember me" support
Let users opt into persistent sessions rather than hardcoding `keep_logged_in=False`. Respect a config option for this.

### Organizer-scoped team sync
Currently teams are matched globally by name. Support scoping team sync to a specific pretix organizer, so multi-organizer deployments don't have naming collisions.

### Webhook-driven sync
Instead of only syncing at login time, subscribe to Discourse webhook events (user group changes, suspensions, anonymizations) to update pretix state in near-real-time. This closes the "stale until next login" gap.

### User profile sync
Sync additional Discourse profile fields (avatar, locale, timezone) to pretix user profiles. Useful for personalization and for meetup organizers seeing attendee info.

### Logout / single sign-out
Implement Discourse's logout webhook or DiscourseConnect logout URL so that logging out of Discourse also ends the pretix session (and vice versa).

### Dry-run / audit mode
Add a mode that logs what team changes *would* happen without applying them. Useful for initial deployment to verify the group-to-team mapping is correct before going live.

### Admin dashboard widget
Show SSO sync status in the pretix admin: last sync time per user, group-to-team mapping overview, users blocked by policy, and API connectivity health.

## Testing

### Add real tests
The test suite is a placeholder. Priority areas for test coverage:
- Signature verification (valid, tampered, missing)
- Nonce verification (valid, missing, replayed)
- Group-to-city parsing edge cases
- Team sync (add, remove, no-op, missing teams)
- Policy enforcement (suspended, silenced, RTBF, 2FA)
- `is_staff` sync behavior
- API failure modes (timeout, 500, invalid JSON)
- Email conflict handling

### Integration test with Discourse
Set up a test Discourse instance (or mock the SSO protocol end-to-end) to verify the full login flow, including edge cases like changed emails and group membership changes between logins.

## Code Quality

### Move config to per-organizer settings
Module-level config means all organizers share one Discourse instance. For multi-tenant pretix deployments, config should be per-organizer or per-event, stored in pretix's settings framework rather than `pretix.cfg`.

### Declare `requests` dependency
Add `requests` to `pyproject.toml` dependencies. It's imported but not declared; the plugin relies on pretix bundling it implicitly.

### Fix comment indentation
Line 134's `# 8. Team Sync` comment is at column 0 inside a function body. Cosmetic, but signals carelessness to reviewers.
