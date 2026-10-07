# Future Work

## Security Hardening

The plugin validates HTTPS, expires and atomically consumes nonces after ten minutes, requires a working Discourse Admin API key, uses DiscourseConnect's signed 2FA assertion for organiser claims, and wraps team membership updates in a transaction. Pretix alone controls staff access. Organiser groups must match `^meetup-organisers-([a-z]+)$`, and every claimed group must resolve to one provisioned Pretix team.

### Active session invalidation
When the enrichment API detects a user is silenced/suspended, invalidate their existing pretix sessions (via Django's session framework) rather than only blocking new logins.

## Robustness

### Tighten RTBF heuristic
The `username.startswith('anon')` check produces false positives for legitimate usernames. Use the Discourse API's anonymization metadata instead, or check for the exact `anonNNNNNN` pattern Discourse generates.

## Features

### Per-team permission mapping
Review whether Pretix needs additional per-team permissions beyond the currently hardcoded order-read and check-in permissions provisioned by the tooling repository.

### "Remember me" support
Let users opt into persistent sessions rather than hardcoding `keep_logged_in=False`. Respect a config option for this.

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
- preservation of Pretix-owned `is_staff` across Forum logins
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
