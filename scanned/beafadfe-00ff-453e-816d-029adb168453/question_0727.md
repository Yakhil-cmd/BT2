# Q727: Cross subprotocol messages

## Question
Can a single malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, or `refresh(...)` and inject `session_id` from one subprotocol/channel into another so `public_key_from_commitments` confuses private vs shared or child vs parent context, leading to Bypass of threshold signature requirements?

## Target
- File/function: `src/dkg.rs::public_key_from_commitments`
- Entrypoint: `keygen(...)`, `reshare(...)`, or `refresh(...)`
- Attacker controls: `commitments`, `protocol message timing`
- Exploit idea: Inject child-channel or cross-channel `session_id` messages where only same-channel traffic should count.
- Invariant to test: Private, shared, parent, and child channel namespaces must not overlap for `session_id` messages.
- Expected Immunefi impact: Bypass of threshold signature requirements
- Fast validation: Run two or more local protocol instances around `keygen(...)`, `reshare(...)`, or `refresh(...)`, let one malicious participant inject conflicting, replayed, or cross-context `session_id` data into `public_key_from_commitments`, and assert whether honest nodes still accept a forged, leaked, or misbound output.
