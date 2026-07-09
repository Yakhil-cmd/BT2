# Q2181: Replay stale context

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and replay a stale `serialized group element` into `batch_compute_lagrange_coefficients` by controlling `points_set`, `x`, so this code path accepts state from an earlier session as current and eventually enables Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::batch_compute_lagrange_coefficients`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x`
- Exploit idea: Capture a valid `serialized group element` from one run and inject it into a fresh run with overlapping participants before the expected check fires.
- Invariant to test: `serialized group element` must be bound to the live session, participant set, and exact transcript that consumes it.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_compute_lagrange_coefficients` that feeds crafted `serialized group element` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
