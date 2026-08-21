# Q3495: nonce monotonicity in verifier::check_and_compute_new_allowance

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling transaction nonce values around the current access-key nonce and the nonce upper bound, drive `runtime/runtime/src/verifier.rs::check_and_compute_new_allowance` to replay or reorder a transaction that the nonce check should already have rejected, breaking the invariant that a transaction is accepted only when its nonce is strictly greater than the key's stored nonce, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `check_and_compute_new_allowance`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: transaction nonce values around the current access-key nonce and the nonce upper bound
- Exploit idea: replay or reorder a transaction that the nonce check should already have rejected
- Invariant to test: a transaction is accepted only when its nonce is strictly greater than the key's stored nonce
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
