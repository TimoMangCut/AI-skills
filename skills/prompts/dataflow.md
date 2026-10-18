# Skill: dataflow

Manually trace how input and sensitive data move through this repository. Begin with inbound handlers and follow calls into services/repositories/clients; inspect configuration and wiring to resolve destinations when possible. Look for outbound HTTP/gRPC clients, ESB/APIM integrations, database/ORM access, caches, message producers/consumers, object/file storage, identity providers, payment/card/loan rails, notification services, scheduled jobs and audit/logging. Do not infer a live dependency from a package reference alone.

Represent each item in `flows` with:
- `direction`: `"inbound"`, `"outbound"`, `"internal"`, `"bidirectional"`, or `"unknown"`;
- `source` and `destination` (include transformation/handler context in `notes`);
- `protocol` and `data_types`;
- `trust_boundary` and `identity_context` (e.g., `"user_jwt_propagated"`, `"service_credentials"`, `"mtls_cert"`, `"unauthenticated"`, `"unknown"`);
- `controls` (timeout, retry, circuit breaker, idempotency, validation, encryption, audit logging);
- `status`, `evidence_ids`, and `notes`.

Mark relationships `observed` only when code/config directly shows them; use `derived` for multi-file traces and `hypothesis` for unconfirmed external/runtime wiring. Capture unknowns such as deployment-only routing, service discovery, sidecars or gateway configuration not present in this repository.
