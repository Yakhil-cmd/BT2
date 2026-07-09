# Q2550: Reuse child-channel state

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `challenge_then_build_rng` so concurrently running sessions reuse a child-channel or waitpoint namespace for `rng`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge_then_build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `challenge_label`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `rng` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `rng`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge_then_build_rng` that feeds crafted `rng` / `then` inputs, then assert whether downstream verification accepts an output that should have been rejected.
