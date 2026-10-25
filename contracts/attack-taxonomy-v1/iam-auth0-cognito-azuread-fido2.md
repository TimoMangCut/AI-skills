# Identity Fabric: Auth0, AWS Cognito, Azure AD, FIDO2/WebAuthn & Internal JWT (`iam-auth0-cognito-azuread-fido2`)

> **Group:** II. Identity, Gateways & Multi-Cloud / On-Prem
> **Product Archetypes:** Identity_SSO_Provider, API_Microservice_Gateway
> **Trigger Signals:** auth0, cognito, azuread, entra, oidc, oauth, saml, fido2, webauthn, jwt, jwks, nimbus, sts, refresh_token

## [ BLOCK: jwt-issuer-audience-and-token-exchange ]
### Multi-Tenant JWT Validation, Audience Isolation & Refresh Token Exchange
- Verify strict validation of `iss`, `aud`, `alg` (no `none` or RS256->HS256 confusion), and `exp`.
- Audit token-exchange and refresh endpoints (e.g., `/exchange-refresh-token`) for missing client authentication, scope escalation, or cross-region token acceptance.

## [ BLOCK: cognito-identity-pools-and-sts-vending ]
### AWS Cognito Unauthenticated Pools, STS Vending & Policy Attachment
- Check Cognito Identity Pools for `AllowUnauthenticatedIdentities` and inspect the IAM/IoT permissions bound to the Unauth Role.
- Audit backend endpoints that vend AWS STS credentials (`/client/credentials`) or attach policies (`/attach-policy`) to ensure caller identity and resource ownership are verified.

## [ BLOCK: fido2-webauthn-and-qr-sso ]
### FIDO2/WebAuthn Attestation/Assertion & Cross-Device QR/SSE Login
- In WebAuthn flows (`/attestation/result`, `/assertion/result`, `/recovery/key`), verify server-side challenge single-use binding, `rpId` verification, and signCount checks.
- In QR-code / SSE login flows (`/qr/:type/:sseEncryptKey/:signature/:nonce`), check for session fixation or cross-user QR approval hijacking.
