# Q1802: gas key nonce partitioning in verifier::verify_and_charge_gas_key_tx_ephemeral

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling multiple gas-key nonce indexes used concurrently from parallel submissions, drive `runtime/runtime/src/verifier.rs::verify_and_charge_gas_key_tx_ephemeral` to break the per-index nonce isolation to double-spend one nonce, breaking the invariant that each gas-key nonce index advances independently and monotonically, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `verify_and_charge_gas_key_tx_ephemeral`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: multiple gas-key nonce indexes used concurrently from parallel submissions
- Exploit idea: break the per-index nonce isolation to double-spend one nonce
- Invariant to test: each gas-key nonce index advances independently and monotonically
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
