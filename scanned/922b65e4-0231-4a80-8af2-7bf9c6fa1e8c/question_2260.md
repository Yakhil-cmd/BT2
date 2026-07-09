# Q2260: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `Lagrange coefficient` variants into `compute_lagrange_coefficient` so different honest parties bind different views of `coefficient` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::compute_lagrange_coefficient`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x_i`, `x`
- Exploit idea: Feed different `Lagrange coefficient` values to different honest parties and test whether `coefficient` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `Lagrange coefficient` / `coefficient` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::compute_lagrange_coefficient` that feeds crafted `Lagrange coefficient` / `coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
