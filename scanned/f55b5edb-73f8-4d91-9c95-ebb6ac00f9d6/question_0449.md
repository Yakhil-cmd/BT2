# Q449: decode panic in transaction::from_nonce

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling truncated and adversarially nested encodings, drive `core/primitives/src/transaction.rs::from_nonce` to panic while decoding an attacker-supplied payload, breaking the invariant that decoding returns typed errors instead of panicking, and leading to RPC node crash or unavailability?

## Target
- File/function: `core/primitives/src/transaction.rs` -> `from_nonce`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: truncated and adversarially nested encodings
- Exploit idea: panic while decoding an attacker-supplied payload
- Invariant to test: decoding returns typed errors instead of panicking
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
