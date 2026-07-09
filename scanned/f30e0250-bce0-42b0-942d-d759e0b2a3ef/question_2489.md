# Q2489: Accept zero or identity input

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` with attacker-chosen `seed` and make `build_rng` accept a zero or identity-valued `forked transcript` that should be rejected, causing Cryptographic flaws?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `seed`
- Exploit idea: Inject zero, identity, or empty-form `forked transcript` values exactly where the helper assumes they cannot appear.
- Invariant to test: Zero or identity-valued `forked transcript` inputs must be rejected before any interpolation, proof, or signature step.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::build_rng` that feeds crafted `forked transcript` / `statement encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
