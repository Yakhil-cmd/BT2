Based on my thorough investigation of the codebase, I have identified a valid analog to the PythOracle out-of-order validation bug.

---

### Title
`skip_stateful_validations` Admits Invoke Transactions with Unverified Signatures for Undeployed Accounts via Overly Broad `account_tx_in_pool_or_recent_block` Check - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function bypasses the account `__validate__` entry point for Invoke transactions with nonce=1 targeting undeployed accounts, relying on `account_tx_in_pool_or_recent_block` to confirm a deploy_account is pending. However, this check returns `true` for **any** transaction in the pool for that address — not specifically a deploy_account. An attacker who observes a legitimate user's pending deploy_account can submit an Invoke with nonce=1 carrying an arbitrary/invalid signature for the same account, and the gateway will admit it to the mempool without running `__validate__`.

### Finding Description

In `extract_state_nonce_and_run_validations`, the stateful validator calls `run_pre_validation_checks`, which calls `skip_stateful_validations`: [1](#0-0) 

The skip condition fires when `tx.nonce() == 1`, `account_nonce == 0`, and `account_tx_in_pool_or_recent_block` returns `true`. When it fires, `run_validate_entry_point` is called with `skip_validate = true`: [2](#0-1) 

This sets `execution_flags.validate = false`, so `StatefulValidator::perform_validations` skips the `__validate__` call entirely: [3](#0-2) 

The code comment claims the check is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is **incorrect**: the check does not distinguish between a deploy_account and any other transaction type in the pool. `account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in `tx_pool` or appears in the mempool's committed/staged state: [4](#0-3) [5](#0-4) 

A legitimate user's deploy_account (nonce=0) for an undeployed account is the only transaction type that can reach the pool for that account (since `__validate__` would fail for any invoke on an undeployed account). Once that deploy_account is in the pool, `account_tx_in_pool_or_recent_block` returns `true` for the account address. An attacker observing this can immediately submit an Invoke with nonce=1 carrying an **arbitrary signature** for the same account. The gateway will admit it without calling `__validate__`.

The normal (non-skip) path enforces `__validate__` for every Invoke: [6](#0-5) 

The skipped path does not — this is the direct analog to `commit()` omitting the publish-timestamp ordering check that `commitRequested()` enforces.

### Impact Explanation

An attacker can inject Invoke transactions with invalid/arbitrary signatures into the mempool for any undeployed account that has a pending deploy_account. These transactions:

1. Are admitted to the mempool without signature verification — **invalid transactions accepted at gateway admission**.
2. Consume mempool capacity, enabling DoS against the deploy_account + invoke UX flow.
3. With fee escalation enabled (`enable_fee_escalation: true` in production config), the attacker can **replace** the legitimate user's nonce=1 invoke with their own invalid one by paying a higher fee, causing the legitimate transaction to be evicted. The attacker's transaction will revert on execution, but the legitimate user's transaction is permanently displaced.

This matches: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

- The attacker only needs to monitor the mempool (via P2P propagation or RPC) for pending deploy_account transactions — a standard, unprivileged operation.
- The deploy_account + invoke UX flow is an explicitly supported and documented feature, making targets common.
- No special privileges, keys, or resources are required beyond submitting a transaction.

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction exists for the account in the pool. For example, add a dedicated `has_pending_deploy_account(address)` query to the mempool that inspects the transaction type, rather than checking for any transaction.

Alternatively, restrict the skip condition to only fire when the mempool can confirm the pending transaction for the account is specifically a `DeployAccount` type.

### Proof of Concept

1. Legitimate user Alice generates a new account address `A` (undeployed, on-chain nonce = 0).
2. Alice submits `deploy_account` (nonce=0) to the gateway. It passes all checks and enters the mempool's `tx_pool`.
3. `mempool.account_tx_in_pool_or_recent_block(A)` now returns `true`.
4. Attacker Bob submits `Invoke { sender: A, nonce: 1, signature: [0xDEAD, 0xBEEF] }` (arbitrary invalid signature) to the gateway.
5. Gateway stateful validator: `account_nonce = 0`, `tx.nonce() = 1`, `account_tx_in_pool_or_recent_block(A) = true` → `skip_stateful_validations` returns `true`.
6. `run_validate_entry_point` is called with `skip_validate = true` → `execution_flags.validate = false` → `__validate__` is **not called**.
7. Bob's invalid-signature Invoke is admitted to the mempool.
8. If `enable_fee_escalation = true` and Bob pays ≥10% more than Alice's nonce=1 invoke, Alice's legitimate invoke is evicted from the mempool. Bob's transaction will revert on execution, permanently blocking Alice's post-deploy invoke. [7](#0-6) [4](#0-3) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L74-95)
```rust
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
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
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
