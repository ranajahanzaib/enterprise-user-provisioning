# Authorization model

The identity provider controls membership but does not directly create application permissions. Tenant operators seed the built-in roles and explicitly bind a stable SCIM group ID to a role from the trusted local CLI.

Permissions are `portal:read`, `reports:read`, `billing:read`, `tickets:read`, and `admin:read`. Default roles: `employee` receives portal access; `billing_viewer` receives portal and billing; `support_agent` receives portal and tickets; `tenant_admin` receives all five. The app checks memberships, approved mappings, role permissions, user state, session state, and tenant state on each request. Unmapped groups grant nothing. There is no HTTP role-mapping admin interface yet.
