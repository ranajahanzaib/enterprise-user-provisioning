# Enterprise User Provisioning

[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![SCIM 2.0](https://img.shields.io/badge/SCIM-2.0-blue)](https://datatracker.ietf.org/doc/html/rfc7643)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Automatically provision, update, authorize, and deprovision SaaS users from an enterprise identity provider (such as Okta, Entra ID, or authentik) using **SCIM 2.0** and **OpenID Connect (OIDC)**.

![Enterprise User Provisioning Overview](docs/screenshots/overview.png)

An employee joins an enterprise. The identity provider provisions the SaaS account and memberships over SCIM. The employee signs in through OIDC. The application links only pre-provisioned identities and evaluates current group-role grants on every protected request. Suspending or deleting the account over SCIM instantly revokes all active sessions.

---

## The Problem It Solves

SaaS multi-tenant applications typically suffer from fragmented identity models:

1. **Uncontrolled Just-In-Time (JIT) Provisioning**: Accepting arbitrary inbound OIDC tokens creates unmanaged shadow accounts without operator approval.
2. **Zombie Sessions on Employee Offboarding**: When an employee is disabled in the IdP, their SaaS application session cookies often remain valid until expiration hours or days later.
3. **Stale Role Grants**: Role memberships baked into JWT claims become outdated when group memberships change before token refresh.
4. **Tenant Data Leakage**: Inadequately isolated tenant data in shared databases allows cross-tenant resource manipulation.

**Enterprise User Provisioning solves this with a zero-trust model:**

- **Strict Pre-Provisioning**: An OIDC ID token alone cannot create an account or grant access; identities must be explicitly linked to pre-provisioned SCIM records.
- **Continuous RBAC Evaluation**: Group-to-role mappings and permissions are evaluated against the database on every protected request.
- **Instant Session Invalidation**: Deactivating or deleting a user via SCIM immediately invalidates all active sessions and rejects subsequent requests.
- **Tenant Isolation**: Composite foreign keys (`tenant_id, id`) and per-tenant HMAC-SHA-256 tokens strictly partition all resources and queries.
- **Append-Only Audit Logging**: All lifecycle changes, token operations, role grants, and authorization denials are logged immutably.

---

## Protocols and Architecture

```mermaid
flowchart LR
  IdP[Enterprise IdP / authentik] -->|SCIM 2.0 Bearer Token| API[Go SCIM API]
  API --> Provision[Provisioning Engine]
  Provision --> DB[(PostgreSQL 16)]
  Browser[Employee Browser] -->|OIDC Auth Code + PKCE| IdP
  Browser --> Portal[Web Portal + Sessions]
  Portal --> Authz[Continuous RBAC Check]
  Authz --> DB
```

### Deprovisioning Lifecycle Sequence

```mermaid
sequenceDiagram
  autonumber
  participant Admin as Enterprise Admin
  participant IdP as Identity Provider (authentik / Okta)
  participant SCIM as Go SCIM API
  participant DB as PostgreSQL
  participant Browser as Employee Session
  Admin->>IdP: Disable employee
  IdP->>SCIM: PATCH /scim/v2/Users/{id} active=false
  SCIM->>DB: Set active=false, revoke app_sessions, append audit_events
  SCIM-->>IdP: 200 OK (ETag updated)
  Browser->>DB: GET /app (Cookie: eup_session)
  DB-->>Browser: 401 Unauthorized (Session Revoked, Set-Cookie: Max-Age=0)
```

---

## Showcase Gallery

| Feature / Screen                                                     | Description                                                                                                                                                                                  |
| :------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ![Authenticated Portal](docs/screenshots/dashboard.png)              | **Authenticated Employee Portal (`/app`)**<br>Displays active authenticated session for provisioned user (`sarah.chen@northstar.example`), evaluating `portal:read` permission in real time. |
| ![Admin Portal](docs/screenshots/admin-portal.png)                   | **Role-Protected Administrative Console (`/app/admin`)**<br>Restricted view accessible only when the user's SCIM group is bound to the `tenant_admin` role.                                  |
| ![CLI Provisioning](docs/screenshots/cli-provisioning.png)           | **Administrative CLI (`provisionctl`)**<br>Tenant creation, secure SCIM bearer token generation (HMAC-SHA-256 at rest), RBAC role seeding, and group-role binding.                           |
| ![SCIM Lifecycle & Audit](docs/screenshots/scim-lifecycle-audit.png) | **Automated SCIM Lifecycle & Real-Time Audit Trail**<br>Execution of end-to-end lifecycle verification (`make demo`) and real-time query of append-only audit logs.                          |
| ![Session Invalidation](docs/screenshots/session-revocation.png)     | **Zero-Trust Session Invalidation Proof**<br>Live demonstration of employee account deactivation via SCIM 2.0 PATCH immediately killing active browser sessions.                             |

---

## Key Features

- **SCIM 2.0 REST Engine (RFC 7643 / RFC 7644 Subset)**:
  - Users and Groups: collection `GET`/`POST`; resource `GET`/`PUT`/`PATCH`/`DELETE`.
  - Service discovery: `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`.
  - Attribute filtering (`eq`, `co`, `sw`, `pr`, `and`) parameterized safely via SQL.
  - Deterministic 1-based pagination with configurable page limits (up to 200).
  - Concurrency control using weak ETags (`W/"<version>"`) and `If-Match` headers.
  - Granular `PATCH` operations supporting active status, department, and group memberships.
- **Explicit OIDC Account Linking**:
  - Tenant-specific OIDC configuration with AES-256-GCM encrypted client secrets.
  - PKCE code challenge and state validation with 5-minute expiry.
  - Requires pre-existing active SCIM record; email matching alone never auto-provisions.
- **Dynamic Group-Role Authorization**:
  - Fine-grained permission system: `portal:read`, `reports:read`, `billing:read`, `tickets:read`, `admin:read`.
  - Roles bound to SCIM groups: `employee`, `billing_viewer`, `support_agent`, `tenant_admin`.
  - Authorization dynamically checked against the database on each request.
- **Administrative CLI (`provisionctl`)**:
  - Full management of tenants, provisioning tokens, OIDC providers, identity links, roles, and audit trails.
  - Token rotation supporting 15-minute grace periods for seamless zero-downtime key rotation.
- **Multi-Tenant Security Architecture**:
  - Composite primary and foreign keys enforce strict tenant boundaries.
  - Keyed HMAC-SHA-256 tokens stored with 20-character prefix indexing.
  - Rate limiting on authentication and login endpoints.

---

## Quick Start

### Prerequisites

- **Go**: 1.25+ (tested on Go 1.27)
- **Docker & Docker Compose**: v2+
- **OpenSSL**: For generating local cryptographic keys

### 1. Configure Environment

Copy the example environment files:

```sh
cp .env.example .env
cp .env.authentik.example .env.authentik
```

Generate secure local development secrets:

```sh
# Generate TOKEN_HASH_SECRET (hex 32 bytes)
openssl rand -hex 32

# Generate OIDC_CONFIG_KEY (unpadded base64 32 bytes)
openssl rand -base64 32 | tr -d '\n='

# Generate database and authentik secrets
openssl rand -base64 36 | tr -d '\n'   # PG_PASS
openssl rand -base64 60 | tr -d '\n'   # AUTHENTIK_SECRET_KEY
```

Populate `.env` with these values:

```ini
TOKEN_HASH_SECRET=your-32-byte-hex-string
OIDC_CONFIG_KEY=your-unpadded-base64-key
DATABASE_URL=postgres://provision:local-only-change-me@localhost:5432/provision?sslmode=disable
PUBLIC_BASE_URL=http://localhost:8080
LISTEN_ADDR=:8080
DEV_MODE=true
COOKIE_SECURE=false
```

_(Note: If port 5432 is already occupied on your host, you can set `PGPORT=5433` in `.env` and adjust `DATABASE_URL` accordingly.)_

### 2. Start PostgreSQL

Start the PostgreSQL service using Docker Compose:

```sh
docker compose up -d postgres
```

### 3. Run the Go Service

Start the application on the host. Database migrations are applied automatically at startup:

```sh
set -a; source .env; set +a
go run ./cmd/server
```

The server listens on `http://localhost:8080`. Verify health endpoints:

```sh
curl http://localhost:8080/healthz
# {"status":"ok"}

curl http://localhost:8080/readyz
# {"status":"ready"}
```

---

## Practical Usage & Workflows

### 1. Tenant & Token Setup via CLI

Create an enterprise tenant and issue an authenticated SCIM bearer token:

```sh
set -a; source .env; set +a

# Create tenant
TENANT_ID=$(go run ./cmd/provisionctl tenant create "Northstar Cloud Systems")
echo "Tenant ID: $TENANT_ID"

# Seed default RBAC roles
go run ./cmd/provisionctl roles seed "$TENANT_ID"

# Generate SCIM token (stored as HMAC-SHA-256 digest)
SCIM_TOKEN=$(go run ./cmd/provisionctl token create "$TENANT_ID" "Okta SCIM" | tail -n 1)
```

### 2. Provision Users & Groups over SCIM 2.0 API

#### Provision User (`POST /scim/v2/Users`)

```sh
curl -X POST http://localhost:8080/scim/v2/Users \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "sarah.chen@northstar.example",
    "externalId": "okta-usr-8820",
    "name": {
      "givenName": "Sarah",
      "familyName": "Chen"
    },
    "displayName": "Sarah Chen",
    "title": "Principal Security Architect",
    "department": "Security",
    "active": true
  }'
```

#### Provision Group (`POST /scim/v2/Groups`)

```sh
curl -X POST http://localhost:8080/scim/v2/Groups \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Security Administrators",
    "externalId": "okta-grp-secadmin",
    "members": [
      {"value": "<USER_UUID>", "type": "User"}
    ]
  }'
```

### 3. Group-Role Binding

Bind the provisioned SCIM group to an application role (`tenant_admin`):

```sh
go run ./cmd/provisionctl roles bind "$TENANT_ID" "<GROUP_UUID>" tenant_admin
```

List assigned roles and their permissions:

```sh
go run ./cmd/provisionctl roles list "$TENANT_ID"
```

### 4. Execute the Automated SCIM Fixture Demo

Run the end-to-end SCIM lifecycle test:

```sh
make demo DEMO_TENANT_ID="$TENANT_ID"
```

This automated fixture executes through the live SCIM HTTP server:

1. User creation in `Support` department.
2. Group creation (`Employees Demo`).
3. Member assignment to group.
4. Department update to `Finance` via `PATCH`.
5. Group member removal via `PATCH`.
6. Account suspension (`active=false`) with verification of state.
7. Account reactivation (`active=true`) and ETag capture.
8. Deletion with optimistic concurrency (`If-Match: W/"<version>"`).

### 5. Inspect the Audit Trail

View immutable append-only audit events for the tenant:

```sh
go run ./cmd/provisionctl audit list "$TENANT_ID"
```

Sample output:

```text
2026-11-22T09:18:04Z	group.deleted	group	ed4f882d-ef56-4a10-86f7-094d4271e628	success
2026-11-22T09:18:04Z	user.deleted	user	2e81b52a-2496-4232-94b1-be30968c7462	success
2026-11-22T09:18:04Z	user.reactivated	user	2e81b52a-2496-4232-94b1-be30968c7462	success
2026-11-22T09:18:04Z	user.suspended	user	2e81b52a-2496-4232-94b1-be30968c7462	success
2026-11-22T09:18:04Z	membership.removed	group	ed4f882d-ef56-4a10-86f7-094d4271e628	success
2026-11-22T09:18:04Z	group.updated	group	ed4f882d-ef56-4a10-86f7-094d4271e628	success
2026-11-22T09:18:04Z	role_mapping.created	group	ed4f882d-ef56-4a10-86f7-094d4271e628	success
2026-11-22T09:18:04Z	membership.added	group	ed4f882d-ef56-4a10-86f7-094d4271e628	success
2026-11-22T09:18:04Z	group.created	group	ed4f882d-ef56-4a10-86f7-094d4271e628	success
2026-11-22T09:18:04Z	user.created	user	2e81b52a-2496-4232-94b1-be30968c7462	success
2026-11-22T09:18:04Z	token.created			success
```

---

## CLI Reference (`provisionctl`)

| Command                                                      | Description                                                         |
| :----------------------------------------------------------- | :------------------------------------------------------------------ |
| `provisionctl tenant create <name>`                          | Create a new isolated enterprise tenant.                            |
| `provisionctl tenant list`                                   | List all registered tenants and active statuses.                    |
| `provisionctl token create <tenant-id> [name]`               | Generate a scoped SCIM bearer token (displayed once).               |
| `provisionctl token list`                                    | List active tokens, prefixes, expiration, and last used timestamps. |
| `provisionctl token rotate <token-id>`                       | Rotate a token; grants 15-minute grace period on old token.         |
| `provisionctl token revoke <token-id>`                       | Instantly revoke a token.                                           |
| `provisionctl roles seed <tenant-id>`                        | Seed default RBAC roles and granular permissions.                   |
| `provisionctl roles list <tenant-id>`                        | List roles and effective permission sets for a tenant.              |
| `provisionctl roles bind <tenant-id> <group-id> <role-id>`   | Authorize a group-to-role binding.                                  |
| `provisionctl roles unbind <tenant-id> <group-id> <role-id>` | Remove a group-to-role binding.                                     |
| `provisionctl users list <tenant-id>`                        | List provisioned active and deprovisioned users.                    |
| `provisionctl groups list <tenant-id>`                       | List provisioned SCIM groups.                                       |
| `provisionctl audit list <tenant-id>`                        | Output chronological audit events for a tenant.                     |
| `provisionctl demo run <tenant-id>`                          | Execute automated SCIM HTTP API lifecycle test suite.               |

---

## Supported SCIM 2.0 Subset

All endpoints reside under `/scim/v2` and require an authenticated tenant-scoped bearer token. Request bodies are limited to 1 MiB.

- **Endpoints**:
  - `GET /scim/v2/ServiceProviderConfig`, `GET /scim/v2/ResourceTypes`, `GET /scim/v2/Schemas`
  - `GET /scim/v2/Users`, `POST /scim/v2/Users`
  - `GET /scim/v2/Users/{id}`, `PUT /scim/v2/Users/{id}`, `PATCH /scim/v2/Users/{id}`, `DELETE /scim/v2/Users/{id}`
  - `GET /scim/v2/Groups`, `POST /scim/v2/Groups`
  - `GET /scim/v2/Groups/{id}`, `PUT /scim/v2/Groups/{id}`, `PATCH /scim/v2/Groups/{id}`, `DELETE /scim/v2/Groups/{id}`
- **Filter Operators**: `eq`, `co`, `sw`, `pr`, and `and` over `userName`, `externalId`, `id`, `displayName`.
- **Concurrency**: Weak ETags (`ETag: W/"<version>"`) and `If-Match` validation on updates and deletes.
- **PATCH Operations**: Explicit paths (`active`, `displayName`, `department`, `name.familyName`) and group `members` add/replace/remove.

See [docs/scim-api.md](docs/scim-api.md) for full endpoint specifications and error handling.

---

## Verification & Testing

Run all unit, integration, and race condition tests:

```sh
# Run standard test suite
go test ./...

# Run clean test suite with race detector (requires TEST_DATABASE_URL)
TEST_DATABASE_URL="postgres://provision:local-only-change-me@localhost:5432/provision?sslmode=disable" \
  go test -count=1 -race ./...

# Run static analysis
go vet ./...

# Build all binaries
go build ./cmd/server ./cmd/provisionctl
```

---

## Documentation Index

- [Architecture & Protocols](docs/architecture.md)
- [SCIM 2.0 API Specifications](docs/scim-api.md)
- [authentik Integration Guide](docs/authentik-setup.md)
- [RBAC & Authorization Model](docs/authorization.md)
- [Account Lifecycle Policy](docs/lifecycle-policy.md)
- [Multi-Tenant Isolation](docs/tenant-isolation.md)
- [Threat Model & Security Design](docs/threat-model.md)
- [Testing Strategy](docs/testing.md)

---

## Contributing

Contributions are welcome! Please review [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before submitting a pull request.


## License & Custom Work

[![Hire me](https://img.shields.io/badge/Open%20to%20work-work%40withrana.com-brightgreen)](mailto:work@withrana.com) [![LinkedIn](https://img.shields.io/badge/LinkedIn-workwithrana-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/workwithrana)
[![Upwork](https://img.shields.io/badge/Upwork-Hire%20Me-14A800?style=flat&logo=upwork&logoColor=white)](https://www.upwork.com/freelancers/~01bbcf6edb91a8df5f)
[![Contra](https://img.shields.io/badge/Contra-Hire%20Me-000000?style=flat)](https://contra.com/ranajahanzaib/)

**License:** MIT, see [LICENSE](LICENSE). Free for personal and commercial use.

**Author:** Rana Jahanzaib

**Need this built for your stack?** Email me what you're working on: work@withrana.com
