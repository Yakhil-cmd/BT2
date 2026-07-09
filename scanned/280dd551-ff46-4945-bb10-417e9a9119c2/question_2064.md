# Q2064: Cross subprotocol messages

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and inject `interpolation set` from one subprotocol/channel into another so `check` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/commitment.rs::check`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `val`, `r`
- Exploit idea: Inject child-channel or cross-channel `interpolation set` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `interpolation set` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::commitment::check` that feeds crafted `interpolation set` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
