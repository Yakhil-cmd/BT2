# Q2504: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `seed` so repeated calls to `build_rng` expose share-dependent structure in `generator binding` or `forked transcript` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `seed`
- Exploit idea: Query `generator binding` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `generator binding` or `forked transcript`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::build_rng` that feeds crafted `generator binding` / `forked transcript` inputs, then assert whether downstream verification accepts an output that should have been rejected.
