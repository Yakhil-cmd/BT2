# Q2306: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `identifiers`, `shares`, `point` so each local sub-check inside `eval_exponent_interpolation` accepts its own `exponent` fragment, but the combined global statement over `polynomial commitment` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_exponent_interpolation`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `identifiers`, `shares`, `point`
- Exploit idea: Make each local check over `exponent` pass independently, then verify whether the combined global statement over `polynomial commitment` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `exponent` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_exponent_interpolation` that feeds crafted `exponent` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
