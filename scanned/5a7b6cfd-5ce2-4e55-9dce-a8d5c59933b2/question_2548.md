# Q2548: Cross subprotocol messages

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and inject `then` from one subprotocol/channel into another so `challenge_then_build_rng` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge_then_build_rng`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `challenge_label`
- Exploit idea: Inject child-channel or cross-channel `then` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `then` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge_then_build_rng` that feeds crafted `then` / `challenge` inputs, then assert whether downstream verification accepts an output that should have been rejected.
