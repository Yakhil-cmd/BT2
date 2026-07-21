Looking at the external bug's core invariant — a threshold/guard check that can be gamed by an attacker to cause DoS or admit illegitimate operations — I need to find an analog in the sequencer's admission path.

After tracing the gateway stateful validation path, I found a directly analogous issue in `skip_stateful_validations`.

---

### Title
Attacker Can Bypass `__validate__` Signature Check for Undeployed Accounts by Front-Running the Deploy-Account + Invoke UX Flow — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` uses `account_tx_in_pool_or_recent_block` as a proxy to confirm a `deploy_account` transaction exists before skipping the `__validate__` entry-point for a nonce-1 invoke from an undeployed account. The proxy check is too broad: it returns `true` for **any** transaction from that address in the pool, not specifically a `deploy_account`. An attacker who observes a victim's `deploy_account` in the mempool can immediately submit a fake invoke (nonce=1, arbitrary/invalid signature) from the victim's address. The gateway skips `__validate__`, admits the unsigned transaction, and the victim's legitimate invoke is rejected with `DuplicateNonce`.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` implements the deploy-account + invoke UX feature: [1](#0-0) 

The three conditions that trigger the skip are:
1. Transaction is an `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)`

When all three hold, the function calls `account_tx_in_pool_or_recent_block` and returns its result as the `skip_validate` flag: [2](#0-1) 

The mempool implementation of this check is: [3](#0-2) 

It returns `true` if **any** transaction from that address is in the pool — including the victim's `deploy_account`. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." The second case is impossible when `account_nonce == 0` (future-nonce invokes require `__validate__` to pass, which requires the account to exist). So the only realistic case is a `deploy_account` in the pool. However, the check does not enforce this — it accepts any pooled transaction as proof.

When `skip_validate = true`, `run_validate_entry_point` sets `validate = false` in the execution flags: [4](#0-3) 

This propagates into `StatefulValidator::perform_validations`, which returns early without calling `__validate__`: [5](#0-4) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce validity and fee escalation — it does **not** verify the signature: [6](#0-5) 

### Impact Explanation

An attacker who observes a victim's `deploy_account` transaction in the mempool can submit a fake invoke (nonce=1, invalid/arbitrary signature) from the victim's address. The gateway admits it without calling `__validate__`. The victim's legitimate invoke is then rejected with `DuplicateNonce`. This satisfies the High impact criterion: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

The fake transaction will eventually revert during batcher execution (the batcher re-runs `__validate__` with `validate=true`), but by then the victim's nonce-1 slot is occupied and their invoke has been rejected. A sustained attacker can repeat this on every resubmission, permanently blocking the victim's first post-deploy invoke.

### Likelihood Explanation

The attack requires front-running the victim's invoke. In practice, a user sending `deploy_account + invoke` simultaneously broadcasts both transactions. The `deploy_account` typically arrives and is pooled first. An attacker monitoring the mempool (via P2P or RPC) can extract the victim's address from the `deploy_account` and immediately submit a fake invoke. The race window is the latency between the `deploy_account` being pooled and the victim's invoke being processed — a realistic window in any distributed or multi-gateway deployment.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a specific `deploy_account_in_pool` query that returns `true` only when a `deploy_account` transaction for the given address is present in the mempool. This closes the gap between the intended invariant ("a deploy_account exists") and the actual check ("any transaction exists").

### Proof of Concept

1. Victim broadcasts `deploy_account` (nonce=0) and `invoke` (nonce=1) simultaneously.
2. Victim's `deploy_account` is pooled; `account_tx_in_pool_or_recent_block(victim_addr)` now returns `true`.
3. Attacker observes the `deploy_account` in the mempool and extracts `victim_addr`.
4. Attacker crafts `invoke(sender=victim_addr, nonce=1, signature=[0xdead])` and submits it to the gateway.
5. Gateway stateless validation: passes (signature length check only, not validity). [7](#0-6) 
6. Gateway stateful validation:
   - `validate_nonce`: passes (`0 ≤ 1 ≤ 0 + max_allowed_nonce_gap`). [8](#0-7) 
   - `validate_by_mempool`: passes (no duplicate hash, nonce in range). [9](#0-8) 
   - `skip_stateful_validations`: returns `true` (nonce=1, account_nonce=0, victim's `deploy_account` is in pool). [2](#0-1) 
   - `run_validate_entry_point`: **skipped** (`validate=false`). [4](#0-3) 
7. Attacker's fake invoke is admitted to the mempool with an invalid signature.
8. Victim's legitimate invoke

### Citations

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L414-424)
```rust
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
```rust
    fn validate_tx_signature_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
    }
```
