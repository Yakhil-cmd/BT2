# Q2576: Reuse child-channel state

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and exploit `fork` so concurrently running sessions reuse a child-channel or waitpoint namespace for `challenge`, letting attacker messages cross sessions and leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::fork`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `data`
- Exploit idea: Run concurrent sessions with overlapping peers and cross-wire `challenge` messages between child-channel namespaces.
- Invariant to test: Concurrent sessions must not share child-channel or waitpoint identity for `challenge`.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::fork` that feeds crafted `challenge` / `challenge-derived RNG` inputs, then assert whether downstream verification accepts an output that should have been rejected.
