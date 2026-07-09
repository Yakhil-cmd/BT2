# Q2101: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `val` so each local sub-check inside `commit` accepts its own `polynomial` fragment, but the combined global statement over `polynomial commitment` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/commitment.rs::commit`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`
- Exploit idea: Make each local check over `polynomial` pass independently, then verify whether the combined global statement over `polynomial commitment` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `polynomial` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::commit` that feeds crafted `polynomial` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
