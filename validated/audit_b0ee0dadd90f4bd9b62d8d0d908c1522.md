Based on my thorough analysis of the codebase, I have identified a real analog vulnerability.

---

### Title
Gateway `skip_stateful_validations` Admits Unsigned Invoke Transactions for Undeployed Accounts — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validation path unconditionally bypasses the `__validate__` entry point (signature verification) for any invoke transaction with `nonce == 1` sent from an address whose on-chain nonce is `0` and which has **any** transaction present in the mempool pool. An attacker who observes a victim's `deploy_account` transaction entering the mempool can immediately submit a crafted invoke transaction with `nonce=1` for the victim's address carrying an arbitrary or invalid signature. The gateway accepts it without running `__validate__`, admitting the unsigned transaction into the mempool.

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which in turn calls `skip_stateful_validations`: [1](#0-0) 

The bypass condition is:

```
tx.nonce() == Nonce(Felt::ONE)   // tx nonce is exactly 1
&& account_nonce == Nonce(Felt::ZERO)  // account not yet deployed on-chain
&& account_tx_in_pool_or_recent_block(sender_address) == true
```

`account_tx_in_pool_or_recent_block` returns `true` whenever the address has **any** transaction in the pool — not specifically a `deploy_account` transaction: [2](#0-1) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, for invoke transactions, `perform_pre_validation_stage` (nonce/fee/balance checks) still runs, but the code returns `Ok(())` immediately after, before calling `validate_tx`: [4](#0-3) 

`validate_tx` is the only place the `__validate__` entry point (signature check) is invoked: [5](#0-4) 

The nonce and fee/balance pre-checks still run, but they are evaluated against the **victim's** address. If the victim pre-funded their address (required for the deploy_account to pay fees), those checks pass for the attacker's transaction too.

### Impact Explanation

An attacker can submit an invoke transaction with `nonce=1` for any victim address that has a `deploy_account` transaction in the mempool, using an arbitrary or invalid signature. The gateway admits this transaction to the mempool without verifying the signature. This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

Concrete consequences:
1. **Mempool pollution / DoS**: The attacker floods the mempool with signature-invalid invoke transactions for any address currently in the deploy-account UX flow.
2. **Victim invoke blocking**: If the attacker's invalid `nonce=1` tx is admitted before the victim's legitimate `nonce=1` invoke tx, the mempool's duplicate-nonce check (`DuplicateNonce`) rejects the victim's legitimate transaction, breaking the deploy_account + invoke UX flow entirely. [6](#0-5) 

### Likelihood Explanation

- The victim's `deploy_account` transaction is publicly observable in the mempool.
- The attacker only needs to know the victim's contract address (derivable from the deploy_account transaction's class hash, salt, and constructor calldata, all of which are public).
- No privileged access is required; any unprivileged network participant can submit transactions to the gateway.
- The attack window is the time between the victim's `deploy_account` entering the mempool and the victim's `nonce=1` invoke transaction being submitted.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** (not just any transaction) exists in the mempool for the sender address. Alternatively, require that the `deploy_account` transaction hash is explicitly provided and verified against the mempool's stored deploy_account tx hash for that address, similar to the `deploy_account_tx_hash` parameter used in the native blockifier path: [7](#0-6) 

### Proof of Concept

1. Victim calls `add_transaction` with a `deploy_account` tx for address `A` (pre-funded with STRK). The tx enters the mempool; `tx_pool.contains_account(A)` is now `true`.
2. Attacker calls `add_transaction` with an invoke tx: `sender_address=A`, `nonce=1`, `signature=[0xdead, 0xbeef]` (invalid).
3. Gateway calls `skip_stateful_validations`: `nonce==1` ✓, `account_nonce==0` ✓, `account_tx_in_pool_or_recent_block(A)==true` ✓ → returns `true`.
4. `run_validate_entry_point` sets `validate=false`; `perform_pre_validation_stage` passes (victim's balance covers fee bounds); `__validate__` is never called.
5. The attacker's unsigned invoke tx is forwarded to the mempool via `add_tx`.
6. When the victim subsequently submits their legitimate `nonce=1` invoke tx, the mempool returns `DuplicateNonce` and rejects it.
7. The attacker's tx is eventually rejected by the batcher when `__validate__` fails during execution, but the victim's UX flow is permanently disrupted for that nonce. [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L306-314)
```rust
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/native_blockifier/src/py_validator.rs (L109-120)
```rust
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
```
