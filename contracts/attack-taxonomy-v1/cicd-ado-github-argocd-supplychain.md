# CI/CD & Supply Chain: Azure DevOps (ADO), GitHub Actions, ArgoCD & Binaries (`cicd-ado-github-argocd-supplychain`)

> **Group:** II. Identity, Gateways & Multi-Cloud / On-Prem
> **Product Archetypes:** CICD_Supply_Chain, Cloud_Infra_IaC
> **Trigger Signals:** azure-pipelines, ado, github/workflows, gitlab-ci, jenkinsfile, argocd, gitops, dockerfile, sbom, cosign, supplychain

## [ BLOCK: ado-and-github-actions-pipeline-injection ]
### Azure DevOps (ADO) & GitHub Actions Expression Injection & Token Permissions
- Check `.github/workflows/*.yml` and `azure-pipelines.yml` for dangerous triggers (`pull_request_target`), unpinned third-party actions/tasks (`@v*` instead of commit SHA), and missing `permissions:` blocks.
- Trace untrusted PR branch names, commit messages, or issue titles interpolated into `run:` / `script:` blocks.

## [ BLOCK: argocd-gitops-and-binary-provenance ]
### ArgoCD GitOps Control Plane & Prebuilt Binary / Dependency Provenance
- Verify authentication, RBAC, and webhook secret validation on ArgoCD (`argocd.ccar-internal`) and container registries.
- Flag unverified prebuilt native binaries (`.so`, `.dll`, `.onnx`) committed directly into repositories or downloaded in `setup.sh` without SHA-256 checksum pinning.
