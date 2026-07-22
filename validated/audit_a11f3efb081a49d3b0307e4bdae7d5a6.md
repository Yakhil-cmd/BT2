### Title
Overly Broad `account_tx_in_pool_or_recent_block` Check in `skip_stateful_validations` Allows Invoke Transaction with Invalid Signature to Bypass Gateway Admission — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function is designed to skip the `__validate__` entry-point call for an invoke transaction with nonce=1 when the account is not yet deployed, as a UX convenience for the deploy-account + invoke flow. However, the guard condition uses `account_tx_in_pool_or_recent_block`, which returns `true` for **any** transaction from that address in the mempool — not specifically a deploy-account transaction. An attacker can exploit this by first submitting a valid deploy-account transaction for a chosen address, then submitting an invoke transaction with nonce=1 carrying an **invalid signature**. The gateway skips signature verification and admits the unauthorized invoke transaction to the mempool.

---

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the function `skip_stateful_validations` decides whether to skip the blockifier's `__validate__` entry-point call:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate = false` and returns immediately without calling `__validate__`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate = false`, the `__validate__` call is skipped entirely:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [3](#0-2) 

The guard condition relies on `account_tx_in_pool_or_recent_block`, which is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

This returns `true` for **any** transaction type from that address — including a deploy-account transaction that the attacker themselves submitted. The code comment claims this is sufficient:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." [5](#0-4) 

This reasoning is incorrect. The presence of a deploy-account transaction in the mempool (submitted by the attacker) does not imply that the subsequent invoke transaction with nonce=1 is authorized. The attacker controls both submissions.

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce ordering and fee escalation — it does not verify the signature:

```rust
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
``` [6](#0-5) 

---

### Impact Explanation

An attacker can admit an invoke transaction carrying an **invalid or forged signature** to the mempool, bypassing the account's `__validate__` entry point entirely at the gateway layer. This breaks the core admission invariant: every invoke transaction entering the mempool must have passed the account's own signature verification. The admitted transaction will revert during blockifier execution (when `validate=true` is enforced for sequencing), but it has already passed the gateway's admission gate and occupies mempool space. This matches the impact category: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

The attack requires no special privileges. Any unprivileged user can:
1. Choose a deterministic address X (from class_hash, salt, constructor_calldata of any deployed account class).
2. Fund address X with enough balance to pass `verify_can_pay_committed_bounds`.
3. Submit a valid deploy-account transaction for X (requires knowing the private key for X, which the attacker generates themselves).
4. Submit an invoke transaction with nonce=1 and an invalid/arbitrary signature.

Steps 1–4 are entirely within the reach of any network participant. The condition `nonce == 1 && account_nonce == 0 && account_in_mempool` is reliably triggerable.

---

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy-account transaction** for the sender address is present in the mempool. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address)` that only returns `true` when the pending transaction for that address is of type `DeployAccount`. Alternatively, the gateway can require the caller to supply the deploy-account transaction hash and verify it is present in the mempool as a deploy-account type before skipping validation.

---

### Proof of Concept

1. Attacker generates a fresh keypair `(sk, pk)` and computes address `X = calculate_contract_address(salt, class_hash, [pk], 0)` for a standard account class (e.g., OpenZeppelin).
2. Attacker funds address `X` with sufficient STRK to cover the maximum fee of the invoke transaction.
3. Attacker submits a valid `DeployAccount` transaction for address `X` signed with `sk`. This passes all gateway validations and enters the mempool. Now `account_tx_in_pool_or_recent_block(X) == true`.
4. Attacker submits an `Invoke` transaction from address `X` with `nonce=1` and a **random/invalid signature** (e.g., all zeros).
5. Gateway evaluates `skip_stateful_validations`: `nonce == 1`, `account_nonce == 0`, `account_in_mempool == true` → returns `true`.
6. `run_validate_entry_point` sets `validate = false` and returns `Ok(())` without calling `__validate__`.
7. The invoke transaction with invalid signature is forwarded to the mempool and admitted.
8. **Result**: An unauthorized invoke transaction (invalid signature) has bypassed the gateway's signature admission check and is now queued for sequencing. [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-356)
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

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );

        // Move state into the blocking task and run CPU-heavy validation.
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
            })
        })
        .await
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::UnknownErrorCode(
                "StarknetErrorCode.InternalError".to_string(),
            ),
            message: format!("Blocking task join error when running the validate entry point: {e}"),
        })?
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::ValidateFailure),
            message: e.to_string(),
        })?;
        Ok(())
    }
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
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
