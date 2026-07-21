### Title
`skip_stateful_validations` Accepts Invoke Transactions Without Signature Verification Due to Overly Broad Mempool Presence Check - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function is designed to skip the `__validate__` entry point (signature verification) for an invoke transaction with nonce=1 when the account's `deploy_account` has not yet been processed on-chain. The guard for this bypass is `account_tx_in_pool_or_recent_block`, which returns `true` if the account has **any** transaction in the mempool pool — not specifically a `deploy_account` transaction. An attacker who knows that a target account (with on-chain nonce=0) has any future-nonce invoke transaction already in the pool can inject a nonce=1 invoke transaction with an arbitrary/invalid signature, bypassing `__validate__` entirely at the gateway admission layer.

### Finding Description

In `extract_state_nonce_and_run_validations`, the gateway reads the on-chain account nonce, runs pre-validation checks, and then conditionally runs the blockifier's `__validate__` entry point: [1](#0-0) 

The `run_pre_validation_checks` calls `skip_stateful_validations` to decide whether to skip `__validate__`: [2](#0-1) 

Inside `skip_stateful_validations`, the bypass condition is: [3](#0-2) 

The comment claims: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This claim is incorrect. `account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in the pool: [4](#0-3) 

`tx_pool.contains_account` checks for any transaction, not specifically a `deploy_account`: [5](#0-4) 

The `run_validate_entry_point` then sets `validate: !skip_validate`, meaning when `skip_validate=true`, the blockifier's `__validate__` is never called at the gateway level: [6](#0-5) 

### Impact Explanation

**Attack scenario:**

1. Account `A` is deployed on-chain with nonce=0 (just deployed, no transactions executed yet).
2. Account `A`'s legitimate owner submits an invoke tx with nonce=5 (passes `__validate__` normally, lands in the mempool pool).
3. An **attacker** (not the account owner) submits an invoke tx with nonce=1 from account `A` carrying an **invalid/arbitrary signature**.
4. Gateway evaluation:
   - `account_nonce = 0` (from on-chain state)
   - `tx.nonce() = 1` → condition `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` is **true**
   - `account_tx_in_pool_or_recent_block(A)` → **true** (the nonce=5 tx is in the pool)
   - `skip_validate = true` → `__validate__` is **not run**
5. The invalid-signature nonce=1 tx is admitted to the mempool without any signature verification.

The gateway's `validate_by_mempool` call (which precedes `skip_stateful_validations`) only checks nonce ordering and fee escalation — it does not verify signatures: [7](#0-6) 

The nonce=1 tx with account_nonce=0 passes the mempool's nonce check (1 ≥ 0, within `max_allowed_nonce_gap`), so `validate_by_mempool` succeeds. The invalid tx is then admitted.

### Likelihood Explanation

The precondition — an account with on-chain nonce=0 that has a future-nonce invoke transaction in the mempool — is a normal operational state. Any account that was just deployed and whose owner submitted a future-nonce transaction (e.g., nonce=2 through nonce=`max_allowed_nonce_gap`) satisfies it. The attacker needs only to observe the mempool (which is public) to identify such accounts and craft the attack. No privileged access is required.

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies the presence of a **`deploy_account` transaction** for the account in the mempool. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address)` that only returns `true` when a `deploy_account` transaction (not any transaction) is pending for that address. Alternatively, the `skip_stateful_validations` logic should inspect the transaction type of the pooled transaction before granting the bypass.

### Proof of Concept

```
1. Deploy account A on-chain (nonce becomes 0).
2. Submit invoke tx T5 from A with nonce=5, valid signature → passes __validate__, enters pool.
3. Submit invoke tx T1 from A with nonce=1, INVALID signature (e.g., all-zero sig):
   - Gateway: account_nonce=0, tx.nonce=1 → enters skip_stateful_validations
   - account_tx_in_pool_or_recent_block(A) = true (T5 is in pool)
   - skip_validate = true → __validate__ NOT called
   - validate_by_mempool: nonce=1 >= account_nonce=0, no duplicate → passes
   - T1 admitted to mempool without signature check
4. Batcher picks up T1, executes it → __validate__ runs, tx reverts (invalid sig)
   but T1 was already admitted, consuming mempool capacity and batcher resources,
   and potentially displacing legitimate transactions.
```

The root cause is at: [8](#0-7) 

The comment's assumption — that `account_tx_in_pool` implies a `deploy_account` is present — is structurally false: `tx_pool.contains_account` is agnostic to transaction type.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
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

**File:** crates/apollo_mempool/src/transaction_pool.rs (L201-203)
```rust
    pub fn contains_account(&self, address: ContractAddress) -> bool {
        self.txs_by_account.contains(address)
    }
```
