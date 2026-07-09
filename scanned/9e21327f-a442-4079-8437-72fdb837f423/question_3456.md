# Q3456: Cross subprotocol messages

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::derive_signing_share(...)` and inject `derive` from one subprotocol/channel into another so `derive_signing_share` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/lib.rs::derive_signing_share`
- Entrypoint: `lib::derive_signing_share(...)`
- Attacker controls: `private_share`
- Exploit idea: Inject child-channel or cross-channel `derive` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `derive` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Construct a deterministic unit or invariant test around `lib::derive_signing_share` that feeds crafted `derive` / `participant set` inputs, then assert whether downstream verification accepts an output that should have been rejected.
