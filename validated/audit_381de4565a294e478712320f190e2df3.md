### Title
Gateway Admits Unauthorized Invoke Transactions via `skip_stateful_validations` Signature Bypass — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the account's `__validate__` entry point (signature verification) for **any** Invoke transaction with `nonce=1` targeting an account whose on-chain nonce is `0` and that has any transaction in the mempool. An unprivileged attacker can exploit this to submit an unauthorized invoke transaction for any victim account that has a pending `deploy_account`, bypassing signature verification at the gateway admission layer. The invalid transaction is admitted to the mempool, executes during block building, fails `__validate__`, is reverted, and the fee is charged from the victim's pre-funded balance.

### Finding Description

`skip_stateful_validations` (lines 429–461 of `stateful_transaction_validator.rs`) returns `skip_validate = true` when three conditions hold simultaneously:

1. The transaction is an `Invoke` with `nonce == Nonce(Felt::ONE)`
2. The account's on-chain nonce is `Nonce(Felt::ZERO)` (account not yet deployed in committed state)
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`

<cite repo="Camomtat/sequencer--006" path="crates/apollo_gateway/