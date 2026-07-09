# Q2270: Substitute app or public key

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and swap `interpolation set` for attacker-chosen `polynomial commitment` while keeping the rest of `points_set`, `x_i`, `x` valid enough that `compute_lagrange_coefficient` produces an accepted unauthorized output, causing Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::compute_lagrange_coefficient`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `points_set`, `x_i`, `x`
- Exploit idea: Substitute application/public-key context late in the flow and check whether the output remains acceptable to downstream verifiers.
- Invariant to test: `interpolation set` outputs must be bound to the exact `polynomial commitment` selected by the honest protocol run.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::compute_lagrange_coefficient` that feeds crafted `interpolation set` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
