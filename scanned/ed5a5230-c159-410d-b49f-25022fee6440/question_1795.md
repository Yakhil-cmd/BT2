# Q1795: balance check before execution in verifier::is_zero_balance_account

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling an account balance exactly at the boundary of cost plus deposit plus storage stake, drive `runtime/runtime/src/verifier.rs::is_zero_balance_account` to start executing a transaction the account cannot fully pay for, breaking the invariant that a transaction is only executed when the signer can cover fees, deposits and storage staking, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `is_zero_balance_account`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: an account balance exactly at the boundary of cost plus deposit plus storage stake
- Exploit idea: start executing a transaction the account cannot fully pay for
- Invariant to test: a transaction is only executed when the signer can cover fees, deposits and storage staking
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
