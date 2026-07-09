# Q2182: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `coefficients` variants into `batch_compute_lagrange_coefficients` so different honest parties bind different views of `polynomial` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::batch_compute_lagrange_coefficients`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x`
- Exploit idea: Feed different `coefficients` values to different honest parties and test whether `polynomial` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `coefficients` / `polynomial` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_compute_lagrange_coefficients` that feeds crafted `coefficients` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
