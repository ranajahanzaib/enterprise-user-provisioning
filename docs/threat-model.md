# Threat model

## Assets and trust boundaries

Assets include provisioned identities, tenant data, SCIM credentials, OIDC client secrets, sessions, group-role mappings, and audit events. Boundaries are the identity provider to SCIM API, browser to portal, portal to OIDC provider, local CLI to PostgreSQL, and each tenant to every other tenant.

## Risks and controls

- **Stolen SCIM token:** high-entropy random token, tenant binding, HMAC-SHA-256 with server-held key, prefix lookup, constant-time digest compare, 90-day expiry, last-used time, 15-minute rotation overlap, revoke CLI, and a per-IP request limit.
- **Cross-tenant SCIM access:** tenant resolved from credential; SQL scopes by tenant; composite foreign keys protect memberships and OIDC links. PostgreSQL integration test covers cross-tenant membership rejection when configured.
- **Email-based account takeover:** OIDC identity links require exact tenant/provider/issuer/subject mapping; email is not used to create or link an account.
- **Forged or replayed OIDC response:** maintained go-oidc verifier validates issuer, audience, expiry, and signing keys; authorization code uses PKCE; nonce and one-time state hash expire in five minutes and bind to an HttpOnly SameSite cookie.
- **OIDC client secret theft from DB:** AES-GCM encrypted at rest using `OIDC_CONFIG_KEY`. Protect and back up this key separately; changing it makes configured secrets unreadable.
- **Stale session after suspension/deletion:** opaque random session IDs are stored as SHA-256 digests; suspension and delete revoke sessions transactionally; every app request checks current user and tenant state.
- **Stale group authorization:** each protected request calculates permission from current memberships and role mappings; group labels do not grant roles.
- **Filter SQL injection:** restricted filter grammar maps known attribute names to static SQL expressions and binds values as parameters.
- **Audit evidence loss:** lifecycle events are inserted in the same transaction for user updates, delete, and group mutations. Audit access is CLI-only. Database-level append-only enforcement against a database owner is outside the current design.
- **Production cookie misuse:** production startup requires secure-cookie mode; cookies are HttpOnly, SameSite=Lax, scoped to `/`, and have an eight-hour server session. Local loopback HTTP is explicitly a dev setting.

## Security limitations

The portal does not implement CSRF tokens for browser POST forms, and the project does not include a browser-based administration interface, database-level audit immutability, an OIDC configuration-key rotation protocol, or an independent security review. Per-IP rate limits are held in process memory and do not coordinate across replicas. Review and address these limitations before using the service in a production identity environment.
