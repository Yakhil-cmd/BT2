# Q2448: Cross subprotocol messages

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and inject `challenge-derived RNG` from one subprotocol/channel into another so `prove_with_nonce` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/crypto/proofs/dlogeq.rs::prove_with_nonce`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `transcript`, `statement`, `witness`, `k`
- Exploit idea: Inject child-channel or cross-channel `challenge-derived RNG` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `challenge-derived RNG` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `crypto::proofs::dlogeq::prove_with_nonce` that feeds crafted `challenge-derived RNG` / `challenge-derived RNG` inputs, then assert whether downstream verification accepts an output that should have been rejected.
