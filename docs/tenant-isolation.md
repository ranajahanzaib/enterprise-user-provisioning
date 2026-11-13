# Tenant isolation

Every SCIM bearer credential maps to a single tenant record. The API never selects a tenant from request body fields, headers, or query parameters. User and group queries include the credential's tenant ID. Membership rows have composite foreign keys `(tenant_id, group_id)` and `(tenant_id, user_id)`, so a cross-tenant relationship cannot be represented by the database.

The CLI can list, revoke, and rotate tokens. Rotation sets a 15-minute expiry on the old token to allow a controlled switch. Token plaintext is shown only at creation. Protect `TOKEN_HASH_SECRET`; rotating that key invalidates all existing provisioning tokens.

OIDC identity links use `(tenant_id, issuer, subject)` uniqueness and provider/user composite tenant keys. The authentication query requires the provider, issuer, subject, tenant, active user, and active tenant to agree.
