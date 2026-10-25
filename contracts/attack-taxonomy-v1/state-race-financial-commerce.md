# State Machines, Race Conditions (TOCTOU), Payments, Billing & E-Commerce (`state-race-financial-commerce`)

> **Group:** I. Web, Mobile & API Core
> **Product Archetypes:** Payment_Billing_Service, Ecommerce_Portal, Subscription_OTA_Commerce
> **Trigger Signals:** payment, billing, invoice, order, cart, checkout, voucher, coupon, wallet, refund, deposit, subscription, idempotency, lock, transaction

## [ BLOCK: toctou-race-and-idempotency ]
### Concurrent State Mutation (TOCTOU), Double-Spend & Missing Idempotency
- Inspect balance/voucher redemptions, refund triggers, OTP verifications, and ownership transfers for read-modify-write without `SELECT ... FOR UPDATE`, atomic conditional update, or distributed lock.
- Verify whether idempotency keys are scoped to `(userId, endpoint, payload_hash)` and cannot be replayed across different parameters.

## [ BLOCK: payment-webhook-and-ota-entitlement ]
### Payment Callback Forgery, Price/Currency Tampering & Paid OTA Entitlement
- Verify cryptographic signature validation and state transition ordering on payment gateway webhooks.
- In paid FOTA/SOTA or e-commerce flows, check whether an attacker can trigger fulfillment/installation before payment settlement completes.
