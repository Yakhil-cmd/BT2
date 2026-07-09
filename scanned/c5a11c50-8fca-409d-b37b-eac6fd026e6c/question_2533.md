# Q2533: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `label`, `dest` so each local sub-check inside `challenge` accepts its own `forked transcript` fragment, but the combined global statement over `generator binding` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `dest`
- Exploit idea: Make each local check over `forked transcript` pass independently, then verify whether the combined global statement over `generator binding` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `forked transcript` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge` that feeds crafted `forked transcript` / `generator binding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
