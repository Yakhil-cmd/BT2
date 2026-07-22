### Title
Gateway `skip_stateful_validations` Bypasses `__validate__` for Invoke Transactions Based on Any Mempool Entry, Not Specifically a `deploy_account` - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validation path uses `account_tx_in_pool_or_recent_block` to decide whether to skip the `__validate__` entry-point call for an invoke transaction. That helper returns `true` for **any** transaction in the mempool for the account, not exclusively a `deploy_account` transaction. An attacker can therefore submit a `deploy_account` for any undeployed address (using a valid, publicly-known class hash), and then immediately submit an invoke with nonce 1 from that address carrying an **invalid signature**. The gateway skips `__validate__`, and the invalid invoke is admitted to the mempool without signature verification.

### Finding Description

`skip_stateful_validations` is the sequencer-native analog of the Cairo handler that