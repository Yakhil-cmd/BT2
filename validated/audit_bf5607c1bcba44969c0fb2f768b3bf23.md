### Title
Gateway Signature Validation Unconditionally Skipped for Any Account with a Pending Pool Transaction, Not Just Pending `deploy_account` - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (signature verification) for any invoke transaction with nonce 1 whenever `account_tx_in_pool_or_recent_block` returns `true`. The check is too broad: it returns `true` for any account that has **any** transaction in the pool or recent block, not exclusively a `deploy_account` transaction. For accounts deployed via factory contracts (class hash set, nonce 0 on-chain), an attacker can first place a valid invoke (nonce 0) in the pool, then submit a second invoke (nonce 1) with an **invalid signature** that bypasses the `__validate__` entry point entirely at the gateway level and is admitted to the mempool.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when three conditions hold simultaneously:

1. The incoming transaction is an `Invoke` with `tx.nonce() == Nonce(Felt::ONE)`.
2. The on-chain account nonce is `Nonce(Felt::ZERO)`.
3. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

When all three hold, the function returns `true` (skip), which propagates to `run_validate_entry_point`: [2](#0-1) 

`execution_flags.validate` is set to `false`, and `StatefulValidator::perform_validations` short-circuits before calling `__validate__`: [3](#0-2) 

The code comment justifies the skip: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This reasoning is incorrect. `account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in the pool: [4](#0-3) 

`tx_pool.contains_account` is true for any transaction type, including plain invoke transactions: [5](#0-4) 

For an account deployed via a factory contract (`deploy_syscall`), the contract exists on-chain with its class hash set but nonce 0. An invoke with nonce 0 from such an account passes `__validate__` normally (the contract exists). Once that nonce-0 invoke is in the pool, `tx_pool.contains_account` returns `true`, satisfying condition 3. A subsequent invoke with nonce 1 and an **arbitrary/invalid signature** then satisfies all three conditions and skips `__validate__` entirely.

The `validate_by_mempool` call that precedes `skip_stateful_validations` does not close this gap — it only checks for duplicate `tx_hash` and stale nonces, not signatures: [6](#0-5) [7](#0-6) 

The mempool also permits multiple transactions at the same nonce (fee escalation), so the attacker's invalid nonce-1 invoke is not rejected as a duplicate nonce: [8](#0-7) 

### Impact Explanation

An unprivileged attacker can inject invoke transactions with **invalid signatures** into the mempool for any account that (a) has nonce 0 on-chain and (b) has any transaction already in the pool. The gateway's admission invariant — that every admitted transaction has passed its account's `__validate__` entry point — is broken. The invalid transactions will revert during sequencer execution (because `new_for_sequencing` sets `validate: true`), but they occupy mempool slots, can displace or delay legitimate transactions, and constitute a sustained DoS vector against any account in the deploy-account-pending state.

This matches: **High. Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

- The mempool is observable; any pending `deploy_account` or nonce-0 invoke is visible.
- The attacker needs only to craft an invoke with nonce 1 and any signature bytes; no cryptographic capability is required.
- Factory-deployed accounts (e.g., multisigs, proxy wallets deployed via `deploy_syscall`) are common in production.
- The window is open for the entire duration the nonce-0 transaction remains unconfirmed.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is pending for the sender address. The mempool should expose a dedicated query such as `has_pending_deploy_account(address) -> bool` that inspects only `DeployAccount`-typed entries. Alternatively, the gateway can inspect the type of the lowest-nonce transaction for the address before deciding to skip `__validate__`.

### Proof of Concept

```
// Setup: account contract deployed via factory, nonce = 0 on-chain, class hash set.

// Step 1 – attacker (or anyone) submits a valid invoke with nonce 0.
//   gateway: account_nonce=0, tx_nonce=0 → nonce check passes, __validate__ runs, signature OK.
//   mempool: tx_pool.contains_account(addr) = true after add_tx.

// Step 2 – attacker submits invoke with nonce 1, GARBAGE signature.
//   gateway stateful path:
//     account_nonce = get_nonce_from_state(addr) = 0          ← on-chain nonce still 0
//     validate_state_preconditions: nonce 1 within gap → OK
//     validate_by_mempool: no duplicate hash, nonce 1 >= 0 → OK
//     skip_stateful_validations:
//       tx.nonce() == 1  ✓
//       account_nonce == 0  ✓
//       account_tx_in_pool_or_recent_block(addr) == true  ✓  (nonce-0 invoke is in pool)
//       → returns true (SKIP)
//     run_validate_entry_point(skip_validate=true):
//       execution_flags.validate = false
//       StatefulValidator::perform_validations → early return, __validate__ NOT called
//   → invalid invoke admitted to mempool.

// Step 3 – sequencer executes the block:
//   nonce-0 invoke executes normally.
//   nonce-1 invoke

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L162-174)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        let TransactionReference { address, nonce: tx_nonce, .. } = tx_reference;
        let account_nonce = self.resolve_nonce(address, incoming_account_nonce);
        if tx_nonce < account_nonce {
            return Err(MempoolError::NonceTooOld { address, tx_nonce, account_nonce });
        }

        Ok(())
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L702-711)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        if self.tx_pool.get_by_tx_hash(tx_reference.tx_hash).is_ok() {
            return Err(MempoolError::DuplicateTransaction { tx_hash: tx_reference.tx_hash });
        }
        self.state.validate_incoming_tx(tx_reference, incoming_account_nonce)
    }
```

**File:** crates/apollo_mempool/src/transaction_pool.rs (L201-203)
```rust
    pub fn contains_account(&self, address: ContractAddress) -> bool {
        self.txs_by_account.contains(address)
    }
```
