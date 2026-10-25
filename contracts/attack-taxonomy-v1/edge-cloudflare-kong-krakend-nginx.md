# Edge & API Gateways: Cloudflare WAF, Kong, KrakenD, HAProxy, Nginx & ALB (`edge-cloudflare-kong-krakend-nginx`)

> **Group:** II. Identity, Gateways & Multi-Cloud / On-Prem
> **Product Archetypes:** Edge_Gateway_Config, API_Microservice_Gateway
> **Trigger Signals:** cloudflare, kong, krakend, haproxy, nginx, envoy, istio, alb, elb, ingress, waf, turnstile, x-forwarded-for

## [ BLOCK: asymmetric-edge-and-direct-origin-bypass ]
### Asymmetric WAF Posture, Bare ALB Exposure & Direct-Origin Bypass
- Check whether regional or staging gateways (e.g., Bare AWS ALBs, GCP direct IPs, DR endpoints) expose the same backend Kong/KrakenD services without Cloudflare WAF protection.
- Verify whether management interfaces (Kong Admin `:8001/:8444`, KrakenD debug/config endpoints, Spring Actuator) are reachable on direct origins.

## [ BLOCK: gateway-header-spoofing-and-contract-shims ]
### Static Gateway Headers (x-device-platform) & Trusted Header Spoofing
- Refute security controls that rely solely on static client headers (`x-device-platform: android`, `x-service-name`).
- Check whether backend services trust `X-Forwarded-For`, `X-Real-IP`, `X-Authenticated-Userid`, or `X-Consumer-*` headers when requests bypass the gateway or arrive via an untrusted ingress.
