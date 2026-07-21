### Title
Gateway Admits Unvalidated-Signature Invoke Transaction via `skip_stateful_validations` UX Bypass - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call (i.e., account signature verification) for any Invoke transaction whose nonce equals 1 and whose sender address appears in the mempool or a recent block. An attacker can exploit this by first submitting a legitimate `deploy_account` transaction (nonce 0) to seed the mempool check, then submitting an Invoke transaction with nonce 1 carrying an **invalid or forged signature**. The gateway admits the second transaction without ever calling `__validate__`, violating the invariant that every admitted transaction must carry a signature that would pass the account's own validation logic.

### Finding Description

The gateway stateful validation path is:

```
extract_state_nonce_and_run_validations
  → run_pre_validation_checks
      → validate_state_preconditions   (nonce range, resource bounds)
      → validate_by_mempool            (duplicate hash + nonce ordering only)
      → skip_stateful_validations      ← returns true → skip_validate = true
  → run_validate_entry_point(skip_validate=true)
      → ExecutionFlags { validate: !skip_validate = false, … }
      → StatefulValidator::perform_validations
          → if !tx.execution_flags.validate { return Ok(()); }  ← __validate__ never called
```

`skip_stateful_validations` returns `true` when all three conditions hold:

1. The transaction is an `ExecutableTransaction::Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

Condition 4 is satisfied as soon as the attacker's `deploy_account` transaction (nonce 0) is accepted into the mempool, because `account_tx_in_pool_or_recent_block` checks both `tx_pool.contains_account` and `state.contains_account`: [2](#0-1) 

`validate_by_mempool` (called before the skip check) only validates duplicate hashes and nonce ordering; it never inspects the signature: [3](#0-2) 

When `skip_validate` is `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [4](#0-3) 

Inside `StatefulValidator::perform_validations`, the `__validate__` call is gated on this flag and is entirely skipped: [5](#0-4) 

### Impact Explanation

The gateway admits an Invoke transaction whose signature has never been verified by the account contract. This breaks the admission invariant: every transaction in the mempool must carry a signature that would pass `__validate__`. The corrupted value is the gateway's admission decision — it returns "accepted" for a transaction that is cryptographically unauthorized.

Matching impact: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

The transaction will eventually fail during block execution (the batcher uses `ExecutionFlags::default()` which has `validate: true`), but it occupies a mempool slot and forces the batcher to attempt execution of an invalid transaction.

### Likelihood Explanation

The attack is fully unprivileged:

1. Generate a fresh key-pair and compute the corresponding Starknet address.
2. Submit a valid `deploy_account` transaction (nonce 0) — this passes full stateful validation and enters the mempool.
3. Immediately submit an Invoke transaction (nonce 1) with an arbitrary or forged signature. The three conditions are now met and `skip_stateful_validations` returns `true`.
4. The Invoke transaction is admitted to the mempool without signature verification.

The only cost is the resource bounds declared in the `deploy_account` transaction. The attacker can repeat this for many fresh addresses, each time seeding the mempool check with a cheap `deploy_account` and then injecting one invalid-signature Invoke per address.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a **`deploy_account` transaction** (not just any transaction) is present in the mempool for the sender address. Alternatively, record the hash of the pending `deploy_account` transaction and verify it matches before skipping `__validate__`. This mirrors the approach already used in `native_blockifier/src/py_validator.rs`, which requires an explicit `deploy_account_tx_hash` argument: [6](#0-5) 

The Rust gateway path should adopt the same pattern: only skip `__validate__` when the caller supplies the hash of a pending `deploy_account` transaction that is confirmed to be in the mempool.

### Proof of Concept

```
# Step 1 – attacker generates address A (account_nonce = 0 on-chain)

# Step 2 – submit valid deploy_account (nonce=0) for address A
POST /gateway/add_transaction
{ type: "DEPLOY_ACCOUNT", nonce: 0, sender_address: A, valid_signature: [...] }
→ accepted; mempool now contains A → account_tx_in_pool_or_recent_block(A) = true

# Step 3 – submit invoke (nonce=1) for address A with INVALID signature
POST /gateway/add_transaction
{ type: "INVOKE", nonce: 1, sender_address: A, signature: [0xdead, 0xbeef] }

# Gateway path:
#   validate_nonce: 0 <= 1 <= 0+max_gap  → OK
#   validate_by_mempool: no duplicate, nonce >= 0  → OK
#   skip_stateful_validations:
#     tx.nonce() == 1  ✓
#     account_nonce == 0  ✓
#     account_tx_in_pool_or_recent_block(A) == true  ✓  (deploy_account is in pool)
#     → returns true
#   run_validate_entry_point(skip_validate=true):
#     execution_flags.validate = false
#     StatefulValidator::perform_validations → early return Ok(())
→ ACCEPTED — invalid-signature invoke is now in the mempool
```

The invalid Invoke transaction is now queued for sequencing. When the batcher eventually attempts to execute it, `__validate__` will be called with `validate: true` (default flags), the account will reject the forged signature, and the transaction will be dropped — but only after consuming batcher resources and occupying a mempool slot.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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

**File:** crates/native_blockifier/src/py_validator.rs (L98-121)
```rust
    pub fn should_run_stateful_validations(
        &mut self,
        account_tx: &AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<bool> {
        if account_tx.tx_type() != TransactionType::InvokeFunction {
            return Ok(true);
        }
        let tx_info = account_tx.create_tx_info();
        let nonce = self.stateful_validator.get_nonce(tx_info.sender_address())?;

        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
    }
```
