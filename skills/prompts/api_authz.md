# Skill: api_authz

Manually inventory inbound application interfaces and map authentication/authorization. Navigate the code yourself (use `coverage_so_far` from prior skills to jump directly to discovered controller/router directories, or `list_dir` with `depth: 2`). Follow route registration to controllers/handlers; inspect attributes/annotations, middleware order, endpoint conventions, filters, authorization policies, JWT/OIDC configuration, claims mapping, custom permission services, and object-level checks. For Go, inspect actual router groups and middleware chaining rather than assuming a middleware is applied globally. For .NET, inspect Minimal API mappings, controller attributes, authorization conventions/policies, filters and middleware setup. For Mobile/Web/Flutter, inspect API client bindings, deep links, route guards, and webviews where applicable. Inspect gRPC/proto, GraphQL, websocket, queue consumers and webhook handlers where present.

For each interface in `endpoints`, identify:
- `method`, `path` (or message/RPC operation), and `handler`;
- `caller_class` (e.g., mobile customer, sales agent, admin portal, internal service, webhook, unknown);
- `authn` (authentication requirement) and `authorization` (rule/policy/middleware);
- `roles` (enforced roles/permissions array);
- `object_level_authz` (explicitly state how object/tenant/account ownership is verified against caller claims to prevent BOLA/IDOR, or `"none_observed"`, `"not_applicable"`, `"unknown"`);
- `sensitivity` (`"low"`, `"medium"`, `"high"`, `"critical"`, or `"unknown"`);
- `status`, `evidence_ids`, and `notes`.

Distinguish "role name exists" from "role is enforced on this endpoint". Trace inherited/global controls before calling an endpoint unauthenticated. If full enforcement cannot be followed, use `unknown` and explain the exact missing hop.

Look especially for IDOR/BOLA (`object_level_authz`), missing function-level authorization, tenant/account boundary mistakes, mass assignment, privilege escalation, weak claim trust, inconsistent policy application and sensitive administrative paths. Do not declare a vulnerability merely because a route is difficult to locate. Keep the API inventory bounded to interfaces you actually inspected and describe coverage limits.
