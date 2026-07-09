# Q2582: Leak sensitive state through output

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and choose `label`, `data` so repeated calls to `fork` expose share-dependent structure in `challenge` or `challenge` that should stay hidden, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::fork`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `data`
- Exploit idea: Query `challenge` repeatedly under attacker-chosen inputs and inspect whether the public output leaks share-dependent structure.
- Invariant to test: Public outputs must not leak hidden share-dependent information about `challenge` or `challenge`.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::fork` that feeds crafted `challenge` / `challenge` inputs, then assert whether downstream verification accepts an output that should have been rejected.
