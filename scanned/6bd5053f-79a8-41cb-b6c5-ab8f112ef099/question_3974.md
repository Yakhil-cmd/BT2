# Q3974: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `secret`, `degree` so each local sub-check inside `generate_polynomial` accepts its own `domain-separated hash` fragment, but the combined global statement over `Lagrange coefficient` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::generate_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `secret`, `degree`
- Exploit idea: Make each local check over `domain-separated hash` pass independently, then verify whether the combined global statement over `Lagrange coefficient` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `domain-separated hash` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::generate_polynomial` that feeds crafted `domain-separated hash` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
