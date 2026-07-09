# Q3922: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `interpolation set`, `polynomial` so each local sub-check inside `extend_with_identity` accepts its own `domain-separated hash` fragment, but the combined global statement over `with` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_identity`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `interpolation set`, `polynomial`
- Exploit idea: Make each local check over `domain-separated hash` pass independently, then verify whether the combined global statement over `with` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `domain-separated hash` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_identity` that feeds crafted `domain-separated hash` / `with` inputs, then assert whether downstream verification accepts an output that should have been rejected.
