### Title
Gateway Stateful Validator Skips `__validate__` Signature Check for Invoke Transactions Targeting Accounts with Pending Deploy — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally bypasses the account's `__validate__` entry-point (and therefore its signature verification) for any Invoke transaction whose nonce is exactly `1` when the on-chain account nonce is `0` and the account already has any transaction in the mempool. An unprivileged attacker who observes a legitimate `deploy_account` transaction in the mempool can immediately submit an Invoke transaction with an **arbitrary/invalid signature** for the same address and have it admitted into the mempool without any cryptographic check.

---

### Finding Description

**Bypass path — `skip_stateful_validations`** [1](#0-0) 

The function returns `true` (skip validation) when all three conditions hold simultaneously:

1. The transaction is an `Invoke` transaction.
2. `tx.nonce() == Nonce(Felt::ONE)` — the submitted nonce is exactly 1.
3. `account_nonce == Nonce(Felt::ZERO)` — the account does not yet exist on-chain.
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [2](#0-1) 

**Effect on the validate entry-point**

When `skip_validate = true`, `run_validate_entry_point` constructs the `AccountTransaction` with `validate: false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, the Invoke branch returns `Ok(())` immediately without ever calling `__validate__`: [4](#0-3) 

`AccountTransaction::validate_tx` also short-circuits on the same flag: [5](#0-4) 

**`account_tx_in_pool_or_recent_block` does not verify transaction type**

The mempool check used to gate the skip does not require the existing transaction to be a `deploy_account`; it returns `true` for any transaction belonging to the address: [6](#0-5) 

`MempoolState::contains_account` checks only key presence in the staged/committed maps: [7](#0-6) 

**Stateless validator does not verify signature content**

The stateless validator only checks signature *length*, not cryptographic validity: [8](#0-7) 

**`validate_by_mempool` does not check signatures either**

The mempool's `validate_tx` only checks nonce ordering and fee-escalation rules: [9](#0-8) 

There is therefore **no guard** in the entire gateway admission path that verifies the cryptographic signature of an Invoke transaction when the skip condition is active.

---

### Impact Explanation

An attacker can submit an Invoke transaction with a completely invalid (e.g., all-zero) signature for any address that currently has a `deploy_account` transaction pending in the mempool. The gateway accepts the transaction without calling `__validate__`, so the transaction is inserted into the mempool. The legitimate user's first Invoke (nonce = 1) is then rejected by the mempool as `DuplicateNonce` (when fee escalation is disabled) or forced to pay a higher fee (when fee escalation is enabled). The attacker can repeat this indefinitely, sustaining a targeted DoS against every new account deployment visible in the mempool.

This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The attack is fully unprivileged. The mempool is observable (transactions are broadcast over P2P), so an attacker can detect any pending `deploy_account` transaction and immediately race to submit a spoofed Invoke. The conditions (`nonce == 1`, `account_nonce == 0`, account in mempool) are trivially satisfied whenever a new account is being deployed. No special knowledge, keys, or permissions are required.

---

### Recommendation

The skip-validate UX feature should be narrowed so that it only applies when the **existing mempool transaction for the account is specifically a `deploy_account` transaction**, and the incoming Invoke transaction's signature is still verified against the **expected** account class (using the class hash from the pending `deploy_account` transaction). Alternatively, the gateway should perform an off-chain signature pre-check using the class hash declared in the pending `deploy_account` before granting the skip. At minimum, the comment's claim that "it is sufficient to check if the account exists in the mempool" should be tightened to require the presence of a `deploy_account` transaction specifically.

---

### Proof of Concept

1. Observe a pending `deploy_account` transaction for address `X` in the mempool (e.g., via P2P gossip or the RPC).
2. Construct an Invoke V3 transaction for address `X` with:
   - `nonce = 1`
   - `sender_address = X`
   - `signature = [0x0, 0x0]` (invalid)
   - Any valid resource bounds and calldata.
3. Submit the transaction to the gateway (`starknet_addInvokeTransaction`).
4. **Expected (correct) behavior**: the gateway calls `__validate__`, which fails because the account contract does not exist yet or the signature is invalid → transaction rejected.
5. **Actual behavior**: `skip_stateful_validations` returns `true` because `nonce == 1`, `account_nonce == 0`, and `account_tx_in_pool_or_recent_block(X) == true` (due to the pending `deploy_account`). `run_validate_entry_point` sets `validate: false` and returns `Ok(())` without calling `__validate__`. The invalid-signature Invoke is inserted into the mempool.
6. The legitimate user's Invoke with `nonce = 1` is now rejected as `DuplicateNonce` by the mempool.
7. Repeat step 2–6 after each block commit to sustain the DoS. [10](#0-9) [11](#0-10)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-194)
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
```
