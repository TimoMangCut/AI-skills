# REST, GraphQL, gRPC/Protobuf & WebSocket API Surfaces (`api-rest-graphql-grpc-websocket`)

> **Group:** I. Web, Mobile & API Core
> **Product Archetypes:** API_Microservice_Gateway, Realtime_WebSocket_Service
> **Trigger Signals:** openapi, swagger, rest, graphql, grpc, protobuf, proto, websocket, ws, wss, ssrf, webhook, fileupload, multipart

## [ BLOCK: openapi-shadow-routes-and-debug-sinks ]
### Undocumented Shadow Routes, Staging Backdoors & Schema Exposure
- Compare code-level route registrations against published OpenAPI/Swagger specs to uncover shadow endpoints.
- Hunt for non-prod/test/debug handlers (`/fake/otp/*`, `/test/user-vehicle/*`, `/api/sample/*`, `/actuator/*`, Django `DEBUG=True` URL dumps) compiled into shared builds.

## [ BLOCK: ssrf-webhooks-and-url-fetchers ]
### Server-Side Request Forgery (SSRF), Webhooks & Media/Avatar Fetchers
- Trace all user-supplied URLs (webhooks, avatar/document imports, OIDC discovery, PDF/headless-browser rendering) to outbound HTTP clients.
- Check if DNS resolution, HTTP redirects (301/302), or IPv6 mapped addresses bypass RFC1918 (`10.x.x.x`) and cloud metadata (`169.254.169.254`) filters.

## [ BLOCK: websocket-and-grpc-stream-auth ]
### WebSocket Upgrade Handshake, Message-Level Authz & gRPC Interceptors
- Verify whether WebSocket (`ws://`/`wss://`) servers validate `Origin`, authenticate the HTTP `101 Switching Protocols` upgrade, AND enforce per-message/per-topic authorization.
- Check gRPC unary and streaming interceptors for unauthenticated reflection or missing metadata token checks.
