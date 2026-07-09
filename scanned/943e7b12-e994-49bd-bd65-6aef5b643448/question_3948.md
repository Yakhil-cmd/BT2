# Q3948: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `interpolation set`, `polynomial` so each local sub-check inside `extend_with_zero` accepts its own `extend` fragment, but the combined global statement over `polynomial` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `interpolation set`, `polynomial`
- Exploit idea: Make each local check over `extend` pass independently, then verify whether the combined global statement over `polynomial` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `extend` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_zero` that feeds crafted `extend` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
