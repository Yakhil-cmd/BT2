# Q2511: Equivocate per recipient

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and send recipient-specific `challenge-derived RNG` variants into `challenge` so different honest parties bind different views of `transcript state` yet still converge on an accepted downstream output, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `dest`
- Exploit idea: Feed different `challenge-derived RNG` values to different honest parties and test whether `transcript state` still converges without detection.
- Invariant to test: All honest parties must observe one consistent `challenge-derived RNG` / `transcript state` transcript for the same round.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge` that feeds crafted `challenge-derived RNG` / `transcript state` inputs, then assert whether downstream verification accepts an output that should have been rejected.
