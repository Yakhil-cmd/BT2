# Q3508: panic in validation path in verifier::verify_nonce

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling malformed borsh, oversized fields, and empty collections, drive `runtime/runtime/src/verifier.rs::verify_nonce` to panic the verifier before the transaction is rejected, breaking the invariant that malformed transactions produce typed errors, never panics, and leading to RPC node crash or unavailability?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `verify_nonce`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: malformed borsh, oversized fields, and empty collections
- Exploit idea: panic the verifier before the transaction is rejected
- Invariant to test: malformed transactions produce typed errors, never panics
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
