# Skill: cross_repo_review

Review the system composed of these repositories, not each repo in isolation. Use only the supplied repo dossiers, cross-repo evidence excerpts and explicit coverage limits. Do not use service names or matching nouns as proof of a connection.

Look for evidenced or reasonably derived interactions: service-to-service HTTP/gRPC; API gateway/mobile-to-backend trust; token/claims forwarding; service identity and mTLS; shared DB or shared storage; event/message producer-consumer pairs; transaction workflows and saga/compensation; duplicate/replay/idempotency across hops; authorization split between caller and callee; data ownership; PII/account/transaction data crossing boundaries; central identity, notification, payment and audit dependencies; timeout/retry amplification; version/schema drift; confused deputy; trust placed in internal network; inconsistent audit/correlation propagation.

Each interaction must cite evidence from one or both repos and be marked observed/derived/hypothesis/unknown. System risks need an explicit multi-repository attack/failure path, assets/impact, priority and concrete validation steps. Do not assert all candidate services are actually connected. Include coverage gaps for missing gateway/deployment/IAM/contract repos or missing source sections. A completed pass is not exhaustive system coverage.
