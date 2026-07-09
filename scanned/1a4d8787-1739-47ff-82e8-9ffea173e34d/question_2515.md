# Q2515: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `label`, `dest` and make `challenge` accept a zero or identity-valued `witness` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `dest`
- Exploit idea: Inject zero, identity, or empty-form `witness` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `witness` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge` that feeds crafted `witness` / `challenge-derived RNG` inputs, then assert whether downstream verification accepts an output that should have been rejected.
