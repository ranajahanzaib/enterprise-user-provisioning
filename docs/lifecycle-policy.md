# Lifecycle policy

`active=false` is distinct from SCIM DELETE. Inactive users remain retrievable and can be reactivated by a later update. Suspension revokes current sessions in the same database transaction. Reactivation does not revive those sessions; a fresh OIDC login is required. DELETE sets a tombstone, deactivates the account, revokes sessions, removes memberships, and appends an audit event in one transaction. Ordinary GET/list calls hide the tombstone. The username can be reused by a newly created resource after deletion.

Protected portal requests look up the opaque server-side session, expiry, revocation, current account status, tenant status, and current group-role permission. Group changes take effect on the next authorization query. In-flight requests cannot be retroactively canceled.
