# Q2075: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `val`, `r` so each local sub-check inside `check` accepts its own `polynomial commitment` fragment, but the combined global statement over `polynomial` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/commitment.rs::check`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Make each local check over `polynomial commitment` pass independently, then verify whether the combined global statement over `polynomial` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `polynomial commitment` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::check` that feeds crafted `polynomial commitment` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
