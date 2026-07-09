# Q2485: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `generator binding` variants into `build_rng` so different honest parties bind different views of `forked transcript` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `seed`
- Exploit idea: Feed different `generator binding` values to different honest parties and test whether `forked transcript` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `generator binding` / `forked transcript` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::build_rng` that feeds crafted `generator binding` / `forked transcript` inputs, then assert whether downstream verification accepts an output that should have been rejected.
