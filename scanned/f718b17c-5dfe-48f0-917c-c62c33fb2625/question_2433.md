# Q2433: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `transcript`, `statement`, `proof` so each local sub-check inside `verify` accepts its own `generator binding` fragment, but the combined global statement over `generator binding` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/dlog.rs::verify`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `proof`
- Exploit idea: Make each local check over `generator binding` pass independently, then verify whether the combined global statement over `generator binding` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `generator binding` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlog::verify` that feeds crafted `generator binding` / `generator binding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
