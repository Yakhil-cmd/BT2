# Q2346: Cross subprotocol messages

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and inject `randomness` from one subprotocol/channel into another so `derive_randomness` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/ecdsa/mod.rs::derive_randomness`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `domain-separated hash`, `serialized scalar`
- Exploit idea: Inject child-channel or cross-channel `randomness` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `randomness` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `ecdsa::derive_randomness` that feeds crafted `randomness` / `serialized group element` inputs, then assert whether downstream verification accepts an output that should have been rejected.
