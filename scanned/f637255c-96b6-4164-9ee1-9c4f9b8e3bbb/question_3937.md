# Q3937: Cross subprotocol messages

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and inject `zero` from one subprotocol/channel into another so `extend_with_zero` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/polynomials.rs::extend_with_zero`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `domain-separated hash`, `serialized scalar`
- Exploit idea: Inject child-channel or cross-channel `zero` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `zero` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::extend_with_zero` that feeds crafted `zero` / `zero` inputs, then assert whether downstream verification accepts an output that should have been rejected.
