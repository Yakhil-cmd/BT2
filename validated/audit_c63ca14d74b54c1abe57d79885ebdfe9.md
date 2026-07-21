### Title
Gateway Admits Invoke Transactions with Invalid Signatures via `skip_stateful_validations` Frontrun on Deploy-Account UX Path — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator is designed to skip `__validate__` (account signature verification) for an invoke with nonce=1 when the account has a pending deploy_account in the mempool. An unprivileged attacker who observes a victim's deploy_account in the mempool can frontrun the victim's first invoke by submitting an invoke with an invalid signature for the victim's address. Because `account_tx_in_pool_or_recent_block` returns `true` (the victim's deploy_account is present), the attacker's invalid invoke bypasses `__validate__` entirely and is admitted to the mempool. The victim's subsequent valid invoke is then rejected due to duplicate nonce or fee-escalation failure.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when three conditions hold simultaneously:

1. The incoming transaction is an `Invoke` with `nonce == 1`
2. The on-chain account nonce is `0` (account not yet deployed)
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

Condition 3 is evaluated by `Mempool::account_tx_in_pool_or_recent_block`, which returns `true` if the address has **any** transaction in the pool or any committed/staged nonce — it does not verify that the pooled transaction is specifically a `deploy_account`: [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `!tx.execution_flags.validate`, the function returns `Ok(())` immediately without calling `__validate__`: [4](#0-3) 

The stateless validator only checks signature **format** (length, structure), not cryptographic validity. Cryptographic validity is exclusively enforced by `__validate__` in the account contract. When that call is skipped, a transaction with a garbage signature passes all gateway checks.

**Attack path:**

1. Victim submits `deploy_account(nonce=0)` for address `A`. It is admitted to the mempool.
2. Attacker observes the deploy_account in the mempool.
3. Attacker crafts `invoke(nonce=1, sender=A, garbage_signature, high_fee)`.
4. Gateway stateless validation passes (format check only).
5. `validate_nonce`: `nonce=1 >= account_nonce=0`, passes. [5](#0-4) 

6. `validate_by_mempool` → `Mempool::validate_tx` passes (no duplicate nonce for `A` with nonce=1 yet, nonce not too old). [6](#0-5) 

7. `skip_stateful_validations`: `nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` (victim's deploy_account is in pool) → returns `true`.
8. `run_validate_entry_point` with `skip_validate=true` → `__validate__` is **not called**.
9. Attacker's invalid invoke is admitted to the mempool.
10. Victim submits `invoke(nonce=1, sender=A, valid_signature, lower_fee)`.
11. `validate_fee_escalation` rejects victim's invoke because attacker's nonce=1 is already pooled with a higher fee. [7](#0-6) 

The attacker's invalid invoke will eventually fail during block execution (blockifier calls `__validate__` unconditionally during execution), but the victim's valid invoke has already been rejected from the mempool.

### Impact Explanation

This is a **High** impact finding matching the category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Two broken invariants:
- **Invalid transaction admitted**: An invoke with a cryptographically invalid signature is accepted by the gateway and placed in the mempool without any signature verification.
- **Valid transaction rejected**: The victim's correctly signed invoke is rejected (duplicate nonce / fee-escalation failure) because the attacker's invalid invoke occupies the nonce slot.

The attacker pays only the gas to submit the invalid invoke (which will be rejected on execution), while the victim's transaction is permanently blocked until the attacker's invalid invoke is evicted or the victim pays an even higher fee.

### Likelihood Explanation

**Medium.** The attack requires:
- Watching the public mempool for deploy_account transactions (trivial).
- Frontrunning the victim's invoke before it arrives (standard mempool frontrunning).
- Paying a higher fee than the victim's invoke (attacker controls this).

No privileged access, no special knowledge of the victim's private key, and no dependency on external systems is required. The window is the time between the victim's deploy_account being admitted and the victim's invoke being submitted — a gap that exists by design in the deploy_account + invoke UX flow.

### Recommendation

`skip_stateful_validations` must verify that the pooled transaction for the sender's address is specifically a `deploy_account`, not just any transaction. The mempool should expose a dedicated query such as `deploy_account_in_pool(address)` that checks the transaction type, or the gateway should pass the deploy_account transaction hash (as `PyValidator::should_run_stateful_validations` does in the native blockifier path) and verify it matches a deploy_account in the pool. [8](#0-7) 

The native blockifier path (`PyValidator::should_run_stateful_validations`) already requires a `deploy_account_tx_hash` parameter to be explicitly provided by the caller, which is a stronger guard. The Rust gateway path should adopt the same approach.

### Proof of Concept

```
# State: address A does not exist on-chain (nonce = 0)

# Step 1: Victim submits deploy_account
POST /add_transaction
{ type: "DEPLOY_ACCOUNT", sender_address: A, nonce: 0, signature: <valid> }
→ Admitted to mempool. account_tx_in_pool_or_recent_block(A) = true.

# Step 2: Attacker frontrunning invoke with invalid signature
POST /add_transaction
{ type: "INVOKE", sender_address: A, nonce: 1, signature: [0x1, 0x2], max_fee: HIGH }
→ Stateless: format OK.
→ validate_nonce: 1 >= 0, OK.
→ validate_by_mempool: no duplicate nonce=1 for A, OK.
→ skip_stateful_validations: nonce==1, account_nonce==0,
     account_tx_in_pool_or_recent_block(A)==true → skip=true.
→ run_validate_entry_point(skip_validate=true): __validate__ NOT called.
→ ADMITTED to mempool with invalid signature.

# Step 3: Victim submits valid invoke
POST /add_transaction
{ type: "INVOKE", sender_address: A, nonce: 1, signature: <valid>, max_fee: LOWER }
→ validate_fee_escalation: nonce=1 already in pool with higher fee → REJECTED.

# Result: invalid transaction in mempool, valid transaction rejected.
``` [9](#0-8) [10](#0-9)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L287-296)
```rust
            _ => {
                let max_allowed_nonce =
                    Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
                if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
                    return Err(create_error(format!(
                        "Invalid transaction nonce. Expected: {account_nonce} <= nonce <= \
                         {max_allowed_nonce}, got: {incoming_tx_nonce}."
                    )));
                }
            }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

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
