# Q1800: expired-block-hash acceptance in verifier::validate_transaction

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling `block_hash` pointing at a stale or forked block, drive `runtime/runtime/src/verifier.rs::validate_transaction` to get a transaction accepted outside its validity window, breaking the invariant that a transaction is only valid while its referenced block hash is within the accepted horizon, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `validate_transaction`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: `block_hash` pointing at a stale or forked block
- Exploit idea: get a transaction accepted outside its validity window
- Invariant to test: a transaction is only valid while its referenced block hash is within the accepted horizon
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
