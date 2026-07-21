### Title
`skip_stateful_validations` bypasses `__validate__` for nonce-1 invoke when any non-deploy-account transaction exists in the mempool for the sender — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry point for invoke transactions with nonce=1 when a `deploy_account` is pending in the mempool (UX improvement for simultaneous deploy+invoke). However, the check `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction in the pool, not just `deploy_account` transactions. An attacker who can place any future-nonce invoke (e.g., nonce=2 with a valid signature) into the mempool for a target account can then submit a nonce=1 invoke with an **invalid signature** that bypasses `__validate__` and is admitted to the mempool.

### Finding Description

In `skip_stateful_validations`:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
```

The function returns `true` (skip validation) when the account has **any** transaction in the pool or recent block. The code comment reads: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* The second case is the broken invariant: future-nonce invokes that passed `__validate__` with their own calldata and signature do **not** justify skipping `__validate__` for a different nonce=1 invoke with potentially different calldata and an invalid signature.

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

This returns `true` for any transaction type, not specifically `deploy_account`.

**Attack path** (requires `max_allowed_nonce_gap >= 2`):

1. Account A exists with nonce=0 (deployed, never sent a transaction).
2. Attacker submits nonce=2 invoke for A with a **valid** signature → passes `validate_nonce` and `__validate__` → admitted to mempool.
3. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
4. Attacker submits nonce=1 invoke for A with an **invalid** signature.
5. `validate_nonce` passes (nonce=1 ≤ 0 + max_gap).
6. `validate_by_mempool` passes (only checks for duplicate hashes and nonce gaps, not signatures).
7. `skip_stateful_validations` returns `true` (nonce=1, account_nonce=0, account in pool).
8. `run_validate_entry_point` sets `execution_flags.validate = false` and returns early — `__validate__` is **never called**.
9. The nonce=1 invoke with invalid signature is admitted to the mempool.

The `run_validate_entry_point` early-return path:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
// ...
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call — never reached when skip_validate=true
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```

### Impact Explanation

An invalid transaction (with a wrong signature) is admitted to the mempool without `__validate__` being called. This allows an attacker to fill the mempool with invalid transactions, causing DoS. The transactions will fail during blockifier execution (when `__validate__` is called with default flags), but they consume mempool slots and network resources before being dropped. This matches the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

### Likelihood Explanation

Requires `max_allowed_nonce_gap >= 2` (so a nonce=2 invoke can be admitted for an account with nonce=0) and the attacker having a valid signature for a future-nonce invoke for the target account. The attacker must control an account or have partial signing capability (e.g., in a multi-sig scenario where they can sign nonce=2 but not nonce=1 with the required threshold). Likelihood is **Low-Medium**.

### Recommendation

`skip_stateful_validations` should specifically check for a `deploy_account` transaction in the pool, not just any transaction. The mempool should expose a dedicated method such as `has_deploy_account_in_pool(address) -> bool` that filters by transaction type. The current `account_tx_in_pool_or_recent_block` check is too broad and conflates two distinct cases.

### Proof of Concept

1. Deploy account A (nonce becomes 0).
2. Submit a nonce=2 invoke for A with a valid signature → admitted to mempool.
3. Submit a nonce=1 invoke for A with an **invalid** signature (e.g., all-zero signature).
4. Observe that step 3 succeeds: `skip_stateful_validations` returns `true`, `__validate__` is skipped, and the transaction is admitted to the mempool.
5. Confirm the nonce=1 invoke is present in the mempool without a valid signature, and that it will fail (revert) when the batcher attempts to execute it.

---

**Key code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-314)
```rust
    #[sequencer_latency_histogram(GATEWAY_VALIDATE_TX_LATENCY, true)]
    async fn run_validate_entry_point(
        &mut self,
        executable_tx: &ExecutableTransaction,
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

                Ok(())
            }
```
