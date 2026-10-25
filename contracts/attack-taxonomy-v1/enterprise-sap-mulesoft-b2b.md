# Enterprise Core: SAP S/4HANA (ICF/Fiori), MuleSoft Banking Shims & B2B Portals (`enterprise-sap-mulesoft-b2b`)

> **Group:** III. Enterprise, Data Lake & AI Systems
> **Product Archetypes:** Enterprise_ERP_B2B, Partner_Integration_Adapter
> **Trigger Signals:** sap, fiori, s4hana, icf, webgui, bapi, rfc, mulesoft, mule, erp, mes, dealer, b2b, immobilizer

## [ BLOCK: mulesoft-and-partner-integration-shims ]
### MuleSoft / Partner Integration Shims & High-Impact Actuation Bypass
- Audit `/external/mule/*` and B2B partner endpoints (e.g., `/immobilizer/set-bank-loaned-status`, dealer warranty/RSA APIs) that act on arrays of VINs or customer accounts.
- Verify whether partner endpoints enforce mTLS / strict client-certificate binding and per-partner tenant scoping, or if any caller with a generic token can trigger fleet-wide actions.

## [ BLOCK: sap-icf-fiori-and-erp-mes-boundary ]
### SAP Web Dispatcher, ICF Service Exposure (`/sap/public/*`, WebGUI) & L4<->L3 Boundary
- Check SAP ICF service trees for exposed ping/info/test nodes, default clients, expired TLS certs on Fiori gateways, and unauthenticated RFC/SOAP bridges between SAP ERP (ISA-95 L4) and factory MES (L3).
