# Authorization, BOLA/IDOR, BFLA & Multi-Tenant / Partner Isolation (`authz-bola-bfla-multitenant`)

> **Group:** I. Web, Mobile & API Core
> **Product Archetypes:** API_Microservice_Gateway, B2B_Partner_Portal, Multi_Tenant_SaaS
> **Trigger Signals:** authz, bola, idor, bfla, rbac, abac, preauthorize, permission, ownership, tenant, vincode, billid, orderid, partnerid

## [ BLOCK: object-ownership-bola-idor ]
### Broken Object Level Authorization (BOLA/IDOR) on Resource Identifiers
- For every endpoint accepting an object identifier (`vinCode`, `billId`, `orderId`, `tokenNumber`, `target` Cognito ID, `partnerId`), verify a deterministic join/check binding the authenticated subject (`sub`/`userId`) to that object.
- Check both read paths (e.g., `/parked-images`, `/bills/{id}`) and state-changing paths (`DELETE /cards/{token}`, `POST /transfer-ownership`, `POST /attach-policy`).

## [ BLOCK: function-level-bfla-and-filter-bypass ]
### Broken Function Level Authorization (BFLA) & Security Filter Chain Bypass
- Compare controller-level and method-level guards across sibling routes (e.g., `/user/**`, `/admin/**`, `/internal/**`).
- Check for path matching discrepancies between API Gateway (Kong/KrakenD/ALB) and backend framework (Spring Security Ant/PathPattern matcher, trailing slash, matrix params `;`).

## [ BLOCK: multi-role-lending-and-delegation ]
### Temporary Delegation, Vehicle Lending/Valet Mode & Ownership Transfer
- Trace lifecycle revocation: when a vehicle/asset is transferred or a secondary driver/valet permission expires, are active JWTs, refresh tokens, AWS IoT policies, and BLE digital keys immediately revoked?
