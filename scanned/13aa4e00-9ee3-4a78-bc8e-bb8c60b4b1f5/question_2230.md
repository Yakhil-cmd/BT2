# Q2230: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `values` so each local sub-check inside `batch_invert` accepts its own `serialized scalar` fragment, but the combined global statement over `polynomial commitment` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::batch_invert`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `values`
- Exploit idea: Make each local check over `serialized scalar` pass independently, then verify whether the combined global statement over `polynomial commitment` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `serialized scalar` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_invert` that feeds crafted `serialized scalar` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
