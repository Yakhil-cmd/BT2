# Q2584: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `label`, `data` so each local sub-check inside `fork` accepts its own `witness` fragment, but the combined global statement over `witness` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::fork`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `data`
- Exploit idea: Make each local check over `witness` pass independently, then verify whether the combined global statement over `witness` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `witness` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::fork` that feeds crafted `witness` / `witness` inputs, then assert whether downstream verification accepts an output that should have been rejected.
