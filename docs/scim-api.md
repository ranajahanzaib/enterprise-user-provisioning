# SCIM API support

Base path `/scim/v2`; tenant-scoped bearer tokens; JSON request limit 1 MiB.

| Area             | Supported behavior                                                                                                            |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Users            | Collection GET/POST; resource GET/PUT/PATCH/DELETE                                                                            |
| User PATCH       | Explicit paths and add/replace no-path objects for supported writable attributes; remove for supported scalar paths           |
| Groups           | Collection GET/POST; resource GET/PUT/PATCH/DELETE                                                                            |
| Group PATCH      | Members add, replace, remove including `members[value eq "id"]`; no-path objects support displayName, externalId, and members |
| User filters     | userName, externalId, id, displayName                                                                                         |
| Group filters    | displayName, externalId, id                                                                                                   |
| Filter operators | eq, co, sw, pr, and                                                                                                           |
| Pagination       | 1-based startIndex/count, maximum 200, stable ordering and totalResults                                                       |
| Metadata         | server UUID, timestamps, configured location, weak ETag/version; If-Match on resource mutations                               |
| Discovery        | ServiceProviderConfig, ResourceTypes, Schemas                                                                                 |
| Bulk/sort        | Not supported; advertised as unsupported                                                                                      |

Supported user fields include core name, emails, active, displayName, title, userType, preferredLanguage, department, and selected enterprise extension fields. Group membership is read-only in the User resource. Group nesting and the full SCIM filter/PATCH grammar are unsupported. No full RFC conformance or live authentik interoperability is claimed.
