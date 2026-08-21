# Q3231: gas-key nonce reuse in action_validation::require_protocol_feature

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling gas key nonce indexes and concurrent transactions using the same key, drive `runtime/runtime/src/action_validation.rs::require_protocol_feature` to replay an action under a nonce the protocol already considered consumed, breaking the invariant that every nonce for a given key is usable at most once, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/action_validation.rs` -> `require_protocol_feature`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: gas key nonce indexes and concurrent transactions using the same key
- Exploit idea: replay an action under a nonce the protocol already considered consumed
- Invariant to test: every nonce for a given key is usable at most once
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
