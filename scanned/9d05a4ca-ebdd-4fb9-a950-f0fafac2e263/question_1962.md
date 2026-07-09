# Q1962: Cross subprotocol messages

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::refresh(...)` and inject `public key` from one subprotocol/channel into another so `refresh` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::refresh`
- Entrypoint: `lib::refresh(...)`
- Attacker controls: `old_participants`, `old_threshold`, `old_public_key`, `old_signing_key`
- Exploit idea: Inject child-channel or cross-channel `public key` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `public key` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::refresh` that feeds crafted `public key` / `public key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
