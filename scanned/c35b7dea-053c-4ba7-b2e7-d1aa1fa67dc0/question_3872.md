# Q3872: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `point` so each local sub-check inside `eval_at_point` accepts its own `polynomial commitment` fragment, but the combined global statement over `eval` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/polynomials.rs::eval_at_point`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `point`
- Exploit idea: Make each local check over `polynomial commitment` pass independently, then verify whether the combined global statement over `eval` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `polynomial commitment` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::eval_at_point` that feeds crafted `polynomial commitment` / `eval` inputs, then assert whether downstream verification accepts an output that should have been rejected.
