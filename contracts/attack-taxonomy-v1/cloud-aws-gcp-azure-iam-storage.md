# Multi-Cloud Infrastructure: AWS, GCP, Azure Storage, IAM, KMS & DNS (`cloud-aws-gcp-azure-iam-storage`)

> **Group:** II. Identity, Gateways & Multi-Cloud / On-Prem
> **Product Archetypes:** Cloud_Infra_IaC, API_Microservice_Gateway
> **Trigger Signals:** aws, s3, ec2, eks, kms, gcp, gcs, cloudrun, azure, blob, appservice, cname, dns, acm, cloudfront

## [ BLOCK: dangling-dns-and-subdomain-takeover ]
### Subdomain Takeover (Azure App Service, S3, CloudFront, GCS) & Expired TLS
- Inspect CNAME records pointing to unprovisioned Azure App Services (`*.azurewebsites.net`), S3/GCS buckets, or dangling CloudFront distributions.
- Verify TLS certificate validity and CA issuance across multi-cloud endpoints.

## [ BLOCK: cloud-storage-pre-signed-urls-and-iam ]
### S3/GCS/Azure Blob ACLs, Pre-Signed URL Scope & Cross-Account IAM
- Check whether staging/prod buckets (`gcs`, `s3`) allow public listing or leak sourcemaps, backups, or vehicle camera images.
- Verify whether shared AWS accounts across dev/staging regions allow cross-environment privilege escalation via overly broad IAM/KMS policies.
