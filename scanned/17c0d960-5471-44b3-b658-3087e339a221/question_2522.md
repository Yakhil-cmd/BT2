# Q2522: Cross subprotocol messages

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and inject `challenge` from one subprotocol/channel into another so `challenge` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/strobe_transcript.rs::challenge`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `label`, `dest`
- Exploit idea: Inject child-channel or cross-channel `challenge` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `challenge` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::strobe_transcript::challenge` that feeds crafted `challenge` / `proof encoding` inputs, then assert whether downstream verification accepts an output that should have been rejected.
