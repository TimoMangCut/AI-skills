# EV Charging Stations (OCPP 1.6/2.0.1, OCPI Roaming) & Battery Swapping Cabinets (`ev-charging-ocpp-ocpi-battery`)

> **Group:** IV. IoT, Automotive, Robotics & OT
> **Product Archetypes:** EV_Charging_CSMS_OCPP, IoT_Telematics_Broker
> **Trigger Signals:** ocpp, ocpi, charging, charger, evse, csms, cpola, vgreen, battery, swap, kwh, metervalues

## [ BLOCK: ocpp-security-profiles-and-billing-integrity ]
### OCPP WebSocket Authentication, MeterValues Billing Integrity & Franchise Revenue
- Check whether OCPP endpoints use plain `ws://` or enforce `wss://` with client certificates (OCPP Security Profile 2/3).
- Trace `StartTransaction`, `StopTransaction`, and `MeterValues`: verify whether a spoofed charger or MITM can inflate kWh readings to defraud free-charging subsidies or franchise revenue sharing (e.g., 750 VND/kWh).

## [ BLOCK: remote-battery-lock-and-cabinet-actuation ]
### Remote Battery Kill-Switch, Cabinet Unlock & Roaming Bus (OCPI)
- Audit authentication, multi-party authorization, and immutable audit logging on remote battery locking/disabling commands and cabinet door/charging actuation.
