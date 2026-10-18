# Verdict examples

- A request plan was generated, but no request was sent: `execution_status = request_plan_only`; chain verdict remains `hypothesized` or `code_supported` according to the code trace.
- Handler appears to omit object ownership validation, but a downstream repository layer has not been inspected: the corresponding step may be `partially_supported`; end-to-end chain cannot be `confirmed`.
- The full code path is directly traced and all prerequisites are evidenced, but the local runtime is unavailable: `code_supported`, not dynamically confirmed.
- An approved local reproduction returns a response containing another synthetic user's secret test field, fixture truth confirms ownership, and an independent code trace establishes the missing authorization check: potentially `confirmed`, subject to counterevidence and evidence audit.
- A request returns `200` but the response is generic and no unauthorized data/state effect is observed: this does not confirm impact.
- A downstream service validates object ownership and denies the request: refute that chain under the tested preconditions; investigate whether another entry path bypasses the downstream check.
