### Title
Gateway Admits Invoke Transactions With Invalid Signatures by Skipping `__validate__` for Accounts With Pending Deploy-Account - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`skip_stateful_validations` in the gateway's stateful path unconditionally skips the account's `__validate__` entry point (signature verification) for any invoke transaction with `nonce == 1` submitted against an address that has *any* transaction in the mempool. Because the mempool check (`account_tx_in_pool_or_recent_block`) is not cryptographically tied to the submitter of the invoke, an unprivileged attacker can submit an invoke with an arbitrary/garbage signature on behalf of any account that has a pending deploy-account, and the gateway will admit it without ever calling `__validate__`.

### Finding Description

`skip_stateful_validations` is the gateway-side analog of the "missing ownership check" pattern. Just as `change_oct_token` mutated privileged state without verifying the caller, `skip_stateful_validations` bypasses the account's authorization check (`__validate__`) without verifying that the invoke submitter is the same party who submitted the deploy-account.

The function's logic is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
async fn skip_stateful_validations(...) -> ... {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await ...;
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, so the blockifier's `StatefulValidator` never calls `__validate__`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

The mempool check `account_tx_in_pool_or_recent_block` returns `true` if the address has *any* transaction in the pool or was seen in a recent committed block:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

There is no cryptographic binding between the deploy-account submitter and the invoke submitter. The check only asks "does this address have *something* in the pool?" — not "did the same key-holder submit both transactions?"

The `StatefulTransactionValidatorConfig` even defines a `max_nonce_for_validation_skip` field, but `skip_stateful_validations` ignores it entirely and hardcodes `nonce == 1`: [4](#0-3) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can submit an invoke transaction with a garbage signature for any address that has a pending deploy-account in the mempool. The gateway admits the transaction without running `__validate__`. The invalid transaction occupies a nonce slot in the mempool. If the attacker bids a higher tip than the legitimate user's invoke, the legitimate user's transaction is displaced via fee-escalation. The attacker's transaction will revert at execution time, but the damage (nonce slot occupation, legitimate tx displacement, mempool pollution) has already occurred.

### Likelihood Explanation

The attack requires only:
1. Observing the public mempool for deploy-account transactions (trivially observable).
2. Submitting an invoke with `nonce=1`, any calldata, and a garbage signature.

No private key knowledge is required. Any unprivileged network participant can execute this.

### Recommendation

The `skip_stateful_validations` check must verify that the invoke's sender address is the *same* address as the deploy-account transaction in the pool, and that the deploy-account transaction was submitted by the same key-holder. At minimum, the check should be restricted to cases where a deploy-account transaction (not just any transaction) is present in the pool for the exact sender address, and the configurable `max_nonce_for_validation_skip` field should be respected. Alternatively, the skip should only be applied after the deploy-account has been executed (i.e., at batcher time, not gateway time), where the account contract is already deployed and can run `__validate__` itself.

### Proof of Concept

1. Legitimate user Alice submits `DeployAccount(address=X, nonce=0, sig=valid)` to the gateway. It passes all checks and enters the mempool.
2. Attacker Bob observes the mempool and sees address X has a pending deploy-account.
3. Bob submits `Invoke(sender=X, nonce=1, calldata=steal_funds, sig=0xdeadbeef)` to the gateway.
4. Gateway stateless validation passes (signature size ≤ limit, resource bounds valid).
5. `validate_state_preconditions`: nonce=1 is within `[0, 0+200]`, resource bounds OK. Passes.
6. `validate_by_mempool`: no duplicate nonce. Passes.
7. `skip_stateful_validations`: `tx.nonce() == 1` ✓, `account_nonce == 0` ✓, `account_tx_in_pool_or_recent_block(X)` → `true` (Alice's deploy-account is in pool). Returns `true`.
8. `run_validate_entry_point` is called with `validate=false`. `__validate__` is **never called**. Bob's garbage-signature invoke is admitted to the mempool.
9. Bob submits with a tip higher than Alice's legitimate invoke. Alice's invoke is displaced by fee-escalation.
10. Bob's invoke executes, `__validate__` runs (at batcher time), fails, transaction reverts — but Alice's invoke is gone from the mempool. [5](#0-4) [1](#0-0)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-410)
```rust
    async fn run_pre_validation_checks(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<bool> {
        self.validate_state_preconditions(executable_tx, account_nonce).await?;
        validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-461)
```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        // check if the transaction nonce is 1, meaning it is post deploy_account, and the
        // account nonce is zero, meaning the account was not deployed yet.
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            let account_address = tx.sender_address();
            debug!("Checking if deploy_account transaction exists for account {account_address}.");
            // We verify that a deploy_account transaction exists for this account. It is sufficient
            // to check if the account exists in the mempool since it means that either it has a
            // deploy_account transaction or transactions with future nonces that passed
            // validations.
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
                .inspect(|exists| {
                    if *exists {
                        debug!("Found deploy_account transaction for account {account_address}.");
                    } else {
                        debug!(
                            "No deploy_account transaction found for account {account_address}."
                        );
                    }
                });
        }
    }

    Ok(false)
}
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L283-295)
```rust
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
```
