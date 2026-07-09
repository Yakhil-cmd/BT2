# Q2537: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `forked transcript` variants into `challenge_then_build_rng` so different honest parties bind different views of `proof encoding` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge_then_build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `challenge_label`
- Exploit idea: Feed different `forked transcript` values to different honest parties and test whether `proof encoding` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `forked transcript` / `proof encoding` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge_then_build_rng` that feeds crafted `forked transcript` / `proof encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
