# Q2272: Reorder rounds

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and reorder attacker-controlled `serialized scalar` messages so `compute_lagrange_coefficient` satisfies an earlier-round check with later-round data, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::compute_lagrange_coefficient`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x_i`, `x`
- Exploit idea: Deliver later-round `serialized scalar` inputs before earlier-round receives complete and watch for premature acceptance.
- Invariant to test: Later-round `serialized scalar` data must never satisfy earlier-round `interpolation set` checks.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::compute_lagrange_coefficient` that feeds crafted `serialized scalar` / `interpolation set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
