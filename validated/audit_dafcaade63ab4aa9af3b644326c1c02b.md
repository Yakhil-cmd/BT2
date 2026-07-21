### Title
Signature Validation Bypass for Invoke Transactions via Overly Permissive `skip_stateful_validations` Check — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator bypasses the `__validate__` entry-point call (which performs signature verification) for invoke transactions with nonce=1 when the account nonce is 0 and **any** transaction from that address exists in the mempool. The check `account_tx_in_pool_or_recent_block` does not verify that the transaction in the pool is specifically a `DeployAccount` transaction. An unprivileged attacker can exploit this by submitting an invoke transaction with an arbitrary (invalid) signature for any address that has a pending `DeployAccount` in the mempool, causing the invalid transaction to be admitted without signature verification.

---

### Finding Description

The `skip_stateful_validations` function is designed to improve UX for the `deploy_account + invoke` pattern: when a user submits both transactions simultaneously, the invoke (nonce=1) should be admitted even though the account doesn't exist