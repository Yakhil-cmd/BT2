# Q2382: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `public_key`, `msg_hash` so each local sub-check inside `verify` accepts its own `polynomial commitment` fragment, but the combined global statement over `domain-separated hash` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/ecdsa/mod.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `public_key`, `msg_hash`
- Exploit idea: Make each local check over `polynomial commitment` pass independently, then verify whether the combined global statement over `domain-separated hash` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `polynomial commitment` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::verify` that feeds crafted `polynomial commitment` / `domain-separated hash` inputs, then assert whether downstream verification accepts an output that should have been rejected.
