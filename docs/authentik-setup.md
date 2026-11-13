# authentik local setup

The checked-in Compose configuration is based on authentik 2026.8.5 and uses PostgreSQL with HTTP exposed on port 9000. A SCIM provider is an application's backchannel provider. See the [official Compose installation guide](https://docs.goauthentik.io/install-config/install/docker-compose) and [SCIM provider setup](https://docs.goauthentik.io/add-secure-apps/providers/scim/create-scim-provider/). The worker does not mount the Docker socket because this setup does not deploy outposts. authentik receives only `.env.authentik`; SaaS provisioning and OIDC encryption keys are not passed to it. This configuration is intended for local development; verify provider behavior and mappings against the authentik version used for deployment.

Run the Go service on the host at `http://localhost:8080`, with authentik in Docker. This keeps the OIDC issuer the same for the browser and Go verifier. The authentik worker reaches the host app at `host.docker.internal` (mapped for Linux in Compose).

## OIDC

1. In authentik, create an OAuth2/OpenID Provider and application.
2. Add redirect URI `http://localhost:8080/oidc/callback`.
3. Use the issuer advertised by the provider metadata. A common local form is `http://localhost:9000/application/o/<slug>/`.
4. Export `.env` in the CLI shell and keep `DEV_MODE=true` for this loopback-only HTTP configuration.
5. Configure with `provisionctl oidc configure TENANT_UUID ISSUER CLIENT_ID CLIENT_SECRET REDIRECT_URL`. The client secret is a command-line argument; avoid shared machines and shell histories that retain sensitive commands.
6. Provision the user over SCIM, seed roles, and explicitly link the exact issuer/subject with `provisionctl identity link PROVIDER_UUID USER_UUID SUBJECT`.

Do not link by email. Compare the subject in the verified OIDC ID token with the immutable authentik identifier represented by SCIM externalId. authentik documents a default where both can be based on the user's hashed ID, but confirm the actual values for your configured provider before linking them ([SCIM provider docs](https://docs.goauthentik.io/add-secure-apps/providers/scim/)).

## SCIM

1. Create an authentik application with a SCIM provider.
2. Set SCIM base URL to `http://host.docker.internal:8080/scim/v2`.
3. Select token authentication and paste the one-time token generated for that tenant.
4. Attach the SCIM provider as a backchannel provider to the application.
5. Configure mappings for userName, externalId, active, profile fields, and memberships; assign users and groups.
6. Exercise create/update/group change/suspend/reactivate/delete; inspect results with SCIM GETs and `provisionctl audit list TENANT_UUID`.

OIDC and SCIM are separate integrations. Validate the configured issuer, subject mapping, and SCIM attribute mappings in the target authentik deployment before relying on the integration.
