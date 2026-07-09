# Q2559: Split global and local checks

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and craft `challenge_label` so each local sub-check inside `challenge_then_build_rng` accepts its own `statement encoding` fragment, but the combined global statement over `witness` is still false and nevertheless accepted, leading to Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge_then_build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `challenge_label`
- Exploit idea: Make each local check over `statement encoding` pass independently, then verify whether the combined global statement over `witness` is still false but accepted.
- Invariant to test: Local checks on decomposed subparts of `statement encoding` must imply the global algebraic statement, not merely independent fragments.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge_then_build_rng` that feeds crafted `statement encoding` / `witness` inputs, then assert whether downstream verification accepts an output that should have been rejected.
