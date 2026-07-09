# Q2209: Swap participant ordering

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with crafted `values` and exploit `batch_invert` so participant ordering or identifier mapping for `interpolation set` differs across nodes, breaking signer-set consistency and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::batch_invert`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `values`
- Exploit idea: Reorder or relabel participant-specific `interpolation set` values and look for divergent Lagrange or identifier handling.
- Invariant to test: Participant identifiers, ordering, and Lagrange weights must map 1:1 to the intended signer set.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_invert` that feeds crafted `interpolation set` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
