# Q2357: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `interpolation set`, `polynomial` so each local sub-check inside `derive_randomness` accepts its own `serialized scalar` fragment, but the combined global statement over `hash output` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/mod.rs::derive_randomness`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `interpolation set`, `polynomial`
- Exploit idea: Make each local check over `serialized scalar` pass independently, then verify whether the combined global statement over `hash output` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `serialized scalar` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::derive_randomness` that feeds crafted `serialized scalar` / `hash output` inputs, then assert whether downstream verification accepts an output that should have been rejected.
