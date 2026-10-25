# Connected Car, AWS IoT Core / EMQX Telemetry, T-Box/MHU & FOTA/SOTA (ISO 21434) (`automotive-connected-car-ota-tbox`)

> **Group:** IV. IoT, Automotive, Robotics & OT
> **Product Archetypes:** IoT_Telematics_Broker, Automotive_Connected_Car, CyberPhysical_OT_Robotics
> **Trigger Signals:** iot, mqtt, emqx, tbox, mhu, fota, sota, ota, vin, telematics, ecu, can, uds, autosar, vehicle, ccar, ccp

## [ BLOCK: mqtt-broker-acl-and-telemetry-surveillance ]
### MQTT Broker ACLs (AWS IoT Core / EMQX), Topic Wildcards & Live GPS/Telemetry Leak
- Verify whether MQTT clients can subscribe to wildcard topics (`#`, `+`, `/mobile/{VIN}/push`, `/server/{VIN}/remctrl`) for VINs they do not own.
- Audit telemetry payloads (2,000+ keys) for leaked owner PII, pre-signed camera URLs, PKI material, or remote command acknowledgments.

## [ BLOCK: fota-sota-signing-and-tbox-pairing ]
### FOTA/SOTA Package Signing, Anti-Rollback & T-Box / Head-Unit (MHU) Pairing
- Trace the OTA trust chain (UN/ECE R156): verify cryptographic signature verification, version anti-rollback checks, and e-contract signing before firmware installation.
- Audit MHU/T-Box pairing flows (`/mhu/send-otp/{vinCode}`, `/tbox/frs`) to ensure staging OTP sinks (`/fake/otp`) or unauthenticated device endpoints cannot hijack vehicle pairing.
