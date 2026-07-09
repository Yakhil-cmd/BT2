# Q2541: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `challenge_label` and make `challenge_then_build_rng` accept a zero or identity-valued `rng` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge_then_build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `challenge_label`
- Exploit idea: Inject zero, identity, or empty-form `rng` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `rng` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge_then_build_rng` that feeds crafted `rng` / `then` inputs, then assert whether downstream verification accepts an output that should have been rejected.
