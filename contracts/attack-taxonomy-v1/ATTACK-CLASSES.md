# ATTACK-CLASSES.md — Master Multi-Domain Attack Taxonomy (LocalSec v3.0 — Vingroup / VinSOC Edition)

> Bộ khung phân loại tấn công chuẩn hóa cho hệ sinh thái đa sản phẩm & Cyber-Physical (WebApp, Mobile, API, Multi-Cloud AWS/GCP/Azure/Cloudflare/ADO/On-Prem, Enterprise SAP/MuleSoft, Data/AI Lakes, Connected Car/IoT/OCPP, Robotics C++/ROS2 & OT BESS/Industrial).
> Mọi companion block khớp với `Product Archetypes` và `Techstack` phải được trích xuất **nguyên văn (verbatim)**, cấm tóm tắt.

## Danh mục 16 Companion Modules theo 4 Nhóm

- **`web-spa-nextjs-ssr`** ([`web-spa-nextjs-ssr.md`](web-spa-nextjs-ssr.md)) — *I. Web, Mobile & API Core*: Web Apps, SPAs (React/Next.js/Angular/Vue), SSR & Low-Code
- **`mobile-android-ios-flutter`** ([`mobile-android-ios-flutter.md`](mobile-android-ios-flutter.md)) — *I. Web, Mobile & API Core*: Mobile Super-Apps & Companion Apps (Android/Kotlin/Smali, iOS/Swift, Flutter, BLE)
- **`api-rest-graphql-grpc-websocket`** ([`api-rest-graphql-grpc-websocket.md`](api-rest-graphql-grpc-websocket.md)) — *I. Web, Mobile & API Core*: REST, GraphQL, gRPC/Protobuf & WebSocket API Surfaces
- **`authz-bola-bfla-multitenant`** ([`authz-bola-bfla-multitenant.md`](authz-bola-bfla-multitenant.md)) — *I. Web, Mobile & API Core*: Authorization, BOLA/IDOR, BFLA & Multi-Tenant / Partner Isolation
- **`state-race-financial-commerce`** ([`state-race-financial-commerce.md`](state-race-financial-commerce.md)) — *I. Web, Mobile & API Core*: State Machines, Race Conditions (TOCTOU), Payments, Billing & E-Commerce
- **`iam-auth0-cognito-azuread-fido2`** ([`iam-auth0-cognito-azuread-fido2.md`](iam-auth0-cognito-azuread-fido2.md)) — *II. Identity, Gateways & Multi-Cloud / On-Prem*: Identity Fabric: Auth0, AWS Cognito, Azure AD, FIDO2/WebAuthn & Internal JWT
- **`edge-cloudflare-kong-krakend-nginx`** ([`edge-cloudflare-kong-krakend-nginx.md`](edge-cloudflare-kong-krakend-nginx.md)) — *II. Identity, Gateways & Multi-Cloud / On-Prem*: Edge & API Gateways: Cloudflare WAF, Kong, KrakenD, HAProxy, Nginx & ALB
- **`cloud-aws-gcp-azure-iam-storage`** ([`cloud-aws-gcp-azure-iam-storage.md`](cloud-aws-gcp-azure-iam-storage.md)) — *II. Identity, Gateways & Multi-Cloud / On-Prem*: Multi-Cloud Infrastructure: AWS, GCP, Azure Storage, IAM, KMS & DNS
- **`onprem-k8s-network-rfc1918`** ([`onprem-k8s-network-rfc1918.md`](onprem-k8s-network-rfc1918.md)) — *II. Identity, Gateways & Multi-Cloud / On-Prem*: Kubernetes (EKS/On-Prem), Internal RFC1918 Subnets & Split-Horizon DNS
- **`cicd-ado-github-argocd-supplychain`** ([`cicd-ado-github-argocd-supplychain.md`](cicd-ado-github-argocd-supplychain.md)) — *II. Identity, Gateways & Multi-Cloud / On-Prem*: CI/CD & Supply Chain: Azure DevOps (ADO), GitHub Actions, ArgoCD & Binaries
- **`enterprise-sap-mulesoft-b2b`** ([`enterprise-sap-mulesoft-b2b.md`](enterprise-sap-mulesoft-b2b.md)) — *III. Enterprise, Data Lake & AI Systems*: Enterprise Core: SAP S/4HANA (ICF/Fiori), MuleSoft Banking Shims & B2B Portals
- **`data-kafka-flink-doris-superset-airflow`** ([`data-kafka-flink-doris-superset-airflow.md`](data-kafka-flink-doris-superset-airflow.md)) — *III. Enterprise, Data Lake & AI Systems*: Data Lakehouse & Streaming: Kafka, Flink, Spark, Doris, Superset, Airflow & Digital Twin
- **`ai-llm-vla-model-serving-datasets`** ([`ai-llm-vla-model-serving-datasets.md`](ai-llm-vla-model-serving-datasets.md)) — *III. Enterprise, Data Lake & AI Systems*: AI/LLM Systems, VLA Model Serving (GGUF/ONNX/Pickle) & Commercial Datasets
- **`automotive-connected-car-ota-tbox`** ([`automotive-connected-car-ota-tbox.md`](automotive-connected-car-ota-tbox.md)) — *IV. IoT, Automotive, Robotics & OT*: Connected Car, AWS IoT Core / EMQX Telemetry, T-Box/MHU & FOTA/SOTA (ISO 21434)
- **`ev-charging-ocpp-ocpi-battery`** ([`ev-charging-ocpp-ocpi-battery.md`](ev-charging-ocpp-ocpi-battery.md)) — *IV. IoT, Automotive, Robotics & OT*: EV Charging Stations (OCPP 1.6/2.0.1, OCPI Roaming) & Battery Swapping Cabinets
- **`robotics-cpp-ros2-ot-scada-bess`** ([`robotics-cpp-ros2-ot-scada-bess.md`](robotics-cpp-ros2-ot-scada-bess.md)) — *IV. IoT, Automotive, Robotics & OT*: Robotics (C++/ZeroMQ/ROS2/MQTT), Energy BESS SCADA (OneATS) & Industrial OT (ISA-95 / ETCS)
