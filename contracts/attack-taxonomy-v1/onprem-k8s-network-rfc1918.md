# Kubernetes (EKS/On-Prem), Internal RFC1918 Subnets & Split-Horizon DNS (`onprem-k8s-network-rfc1918`)

> **Group:** II. Identity, Gateways & Multi-Cloud / On-Prem
> **Product Archetypes:** Cloud_Infra_IaC, OnPrem_Enterprise_Network
> **Trigger Signals:** kubernetes, k8s, helm, docker, container, rfc1918, 10.135, 10.133, 10.228, 10.250, vpc, subnet, onprem

## [ BLOCK: internal-dns-leak-and-vpc-colocation ]
### Split-Horizon DNS Leaks (RFC1918 10.x) & High-Blast VPC Co-Location
- Identify internal hostnames (`10.135.x.x`, `10.133.x.x`, `10.228.x.x`, `10.250.x.x`) leaked in public DNS, config files, or OpenAPI `servers[]` blocks.
- Assess co-location blast radius where critical control planes (ArgoCD, Central Auth, KMS, Core DB, Doris/Flink/Superset) share the same internal IP or K8s node without NetworkPolicy isolation.

## [ BLOCK: k8s-manifests-helm-and-service-mesh ]
### Kubernetes RBAC, Pod Security, ServiceAccount Tokens & East-West Trust
- Audit Helm charts and K8s manifests for `privileged: true`, hostPath mounts, automounted ServiceAccount tokens, and unauthenticated internal service ports (`:8000`, `:8202`).
