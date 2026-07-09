# Q3821: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `deserializer` so each local sub-check inside `deserialize` accepts its own `Lagrange coefficient` fragment, but the combined global statement over `polynomial` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::deserialize`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `deserializer`
- Exploit idea: Make each local check over `Lagrange coefficient` pass independently, then verify whether the combined global statement over `polynomial` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `Lagrange coefficient` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::deserialize` that feeds crafted `Lagrange coefficient` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
