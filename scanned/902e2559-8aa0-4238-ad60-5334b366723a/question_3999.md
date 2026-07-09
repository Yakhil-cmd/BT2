# Q3999: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `v` so each local sub-check inside `set_non_identity_constant` accepts its own `set` fragment, but the combined global statement over `serialized scalar` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::set_non_identity_constant`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `v`
- Exploit idea: Make each local check over `set` pass independently, then verify whether the combined global statement over `serialized scalar` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `set` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::set_non_identity_constant` that feeds crafted `set` / `serialized scalar` inputs, then assert whether downstream verification accepts an output that should have been rejected.
