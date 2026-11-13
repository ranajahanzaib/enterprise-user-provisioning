# Architecture

The service is a Go modular monolith with a SCIM HTTP handler, a pgx connection pool, and PostgreSQL persistence. Provisioning bearer credentials resolve to one tenant before a SCIM operation is handled. The database schema uses tenant-aware foreign keys for user/group memberships. User deletion is represented by a tombstone timestamp.

SCIM and OIDC have separate responsibilities. SCIM provisions identity records; OIDC authenticates a person and links the verified issuer/subject to an existing provisioned record. The app stores only hashed opaque sessions and checks current account state and group-role grants on protected requests.

```mermaid
sequenceDiagram
  participant I as Identity Provider
  participant S as SCIM API
  participant D as Provisioning Service
  participant P as PostgreSQL
  I->>S: Bearer-authenticated SCIM request
  S->>P: Resolve token to one tenant
  S->>D: Validate scoped operation
  D->>P: Transactional user/group mutation
  P-->>I: SCIM resource response
```
