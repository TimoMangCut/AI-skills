# Skill: threat_model

Create a repository-level threat model from inspected evidence, the profile, API/authz inventory and dataflow. Do not manufacture code findings. The goal is to identify realistic threat scenarios and control assumptions that deserve security review.

For each threat include: STRIDE category or a clearly named banking abuse category; asset; plausible actor/capability; concrete preconditions and abuse path; impact; likelihood rationale (not a numeric guess detached from context); existing controls only when evidenced; control gaps as observed or hypothesized; priority; evidence IDs; validation needed.

Cover applicable risks such as account/customer isolation failure, transaction amount/payee tampering, replay and duplicate processing, idempotency gaps, authorization/entitlement abuse, session/token misuse, service identity confusion, event spoofing/replay, sensitive data exposure, audit repudiation, secrets exposure, dependency compromise, and availability/resilience failure. Do not assume every scenario applies. Use `observed` for an evidenced unsafe condition, `derived` for a trace-backed scenario, and `hypothesis` when a relevant control/deployment is unknown. A threat can be valid as a design hypothesis without asserting a confirmed vulnerability. Explicitly list assumptions and unknowns.
