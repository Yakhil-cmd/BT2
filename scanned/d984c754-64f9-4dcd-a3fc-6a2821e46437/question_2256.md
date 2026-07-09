# Q2256: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `interpolation set`, `polynomial` so each local sub-check inside `commit_polynomial` accepts its own `interpolation set` fragment, but the combined global statement over `polynomial commitment` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::commit_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `interpolation set`, `polynomial`
- Exploit idea: Make each local check over `interpolation set` pass independently, then verify whether the combined global statement over `polynomial commitment` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `interpolation set` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::commit_polynomial` that feeds crafted `interpolation set` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
