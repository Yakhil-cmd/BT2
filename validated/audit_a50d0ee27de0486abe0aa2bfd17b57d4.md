### Title
Gateway Signature Verification Bypass via `skip_stateful_validations` for Nonce-1 Invoke Transactions — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful validation path contains a deliberate UX shortcut (`skip_stateful_validations`) that, when triggered, causes the `__validate__` entry point (the account's signature-verification function) to be **completely skipped** before a transaction is admitted to the mempool. An unprivileged attacker who observes a `deploy_account` transaction for any address in the mempool can exploit this path to inject an Invoke transaction carrying an **arbitrary or invalid signature** for that address, bypassing the only cryptographic authorization check in the gateway admission flow.

---

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function returns `true` (skip validation) when all three conditions hold simultaneously:

1. The transaction is `ExecutableTransaction::Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)` (nonce is exactly 1)
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed)
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`

**How the skip propagates**

`run_pre_validation_checks` calls `skip_stateful_validations` and returns the boolean to `extract_state_nonce_and_run_validations`: [2](#0-1) 

`run_validate_entry_point` then constructs `ExecutionFlags` with `strict_nonce_check = false` and, critically, `validate: !skip_validate`: [3](#0-2) 

When `skip_validate = true`, `validate` is `false`. Inside `StatefulValidator::perform_validations`, the Invoke branch calls `perform_pre_validation_stage` (nonce range check only) and then immediately returns `Ok(())` without ever calling `validate_tx` (the `__validate__` entry point): [4](#0-3) 

**What the mempool's `validate_tx` checks**

The mempool's own `validate_tx` only validates nonce ordering and fee escalation — it performs no signature verification: [5](#0-4) 

**The nonce check that does run is insufficient**

`handle_nonce` with `strict = false` only requires `account_nonce <= incoming_tx_nonce`. With account_nonce=0 and tx_nonce=1, this passes and the nonce is incremented in the ephemeral cached state (discarded after validation): [6](#0-5) 

---

### Impact Explanation

An attacker can submit an Invoke transaction for any address that has a pending `deploy_account` in the mempool, using a completely fabricated signature. The transaction passes all gateway checks and is admitted to the mempool without any cryptographic authorization:

- **Nonce range check** (`validate_nonce`): passes — `0 <= 1 <= max_gap` [7](#0-6) 
- **Mempool `validate_tx`**: passes — nonce ordering only, no signature check [5](#0-4) 
- **`skip_stateful_validations`**: returns `true` — account has a tx in mempool, nonce=1, account_nonce=0 [8](#0-7) 
- **`__validate__` entry point**: **never called** — `validate: false` [9](#0-8) 

The attacker's transaction occupies a mempool slot for the victim's account at nonce=1. Because the mempool enforces uniqueness per (address, nonce), this can **displace or block the legitimate nonce-1 transaction** the victim intended to send after their deploy_account. The attacker's transaction will revert during block execution (because `new_for_sequencing` sets `validate: true`), but the damage — mempool slot occupation and potential sequencing delay — is already done.

This matches the impact category: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

- **Unprivileged**: Any observer of the public mempool or gateway can see pending `deploy_account` transactions and the target address.
- **Low cost**: The attacker only needs to submit a well-formed Invoke transaction (valid resource bounds, valid sender address format) with nonce=1 and any signature bytes.
- **Stateless checks pass**: The stateless validator checks resource bounds, calldata size, and DA modes — none of these involve signature content. [10](#0-9) 
- **Window**: The window is open from the moment a `deploy_account` enters the mempool until it is committed in a block.

---

### Recommendation

The `skip_stateful_validations` shortcut should not suppress signature verification entirely. Instead, the gateway should defer the signature check rather than skip it. Two concrete options:

1. **Defer, don't skip**: Accept the transaction into the mempool but mark it as "pending signature verification." Run `__validate__` once the `deploy_account` is committed and the account contract exists.

2. **Restrict the skip to signature-only failure**: Run `perform_pre_validation_stage` (nonce + fee) but still attempt `__validate__`. If it fails solely because the contract does not exist yet (class hash is zero / entry point not found), treat that specific error as acceptable for the UX skip — reject all other `__validate__` failures.

At minimum, the current behavior should be documented as a known admission invariant violation and the mempool should enforce that only one nonce-1 transaction per undeployed address can be admitted via this path, limiting the DoS surface.

---

### Proof of Concept

```
1. Victim submits deploy_account for address 0xVICTIM (nonce=0).
   → deploy_account enters mempool.
   → account_tx_in_pool_or_recent_block(0xVICTIM) now returns true.

2. Attacker submits Invoke for 0xVICTIM, nonce=1, signature=[0xDEAD, 0xBEEF].

3. Gateway stateless validator: passes (valid resource bounds, valid address).

4. Gateway stateful validator:
   a. get_nonce_from_state(0xVICTIM) → 0  (account not deployed)
   b. validate_nonce: 0 <= 1 <= max_gap  → OK
   c. validate_by_mempool: nonce ordering OK  → OK
   d. skip_stateful_validations:
        tx.nonce()==1 ✓, account_nonce==0 ✓,
        account_tx_in_pool_or_recent_block(0xVICTIM)==true ✓
        → returns true (SKIP)
   e. run_validate_entry_point(skip_validate=true):
        ExecutionFlags { validate: false, ... }
        perform_pre_validation_stage: handle_nonce(strict=false) → 0<=1 → OK
        if !tx.execution_flags.validate { return Ok(()); }  ← __validate__ NEVER CALLED
        → returns Ok(())

5. Attacker's transaction with invalid signature is admitted to the mempool.
   Nonce-1 slot for 0xVICTIM is now occupied by attacker's transaction.

6. Victim's legitimate nonce-1 invoke is rejected by mempool (DuplicateNonce).

7. During block execution, attacker's tx runs __validate__ → reverts.
   But victim's nonce-1 tx was never admitted; victim must resubmit.
``` [1](#0-0) [11](#0-10) [4](#0-3)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-95)
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L478-503)
```rust
    fn handle_nonce(
        state: &mut dyn State,
        tx_info: &TransactionInfo,
        strict: bool,
    ) -> TransactionPreValidationResult<()> {
        if tx_info.is_v0() {
            return Ok(());
        }

        let address = tx_info.sender_address();
        let account_nonce = state.get_nonce_at(address)?;
        let incoming_tx_nonce = tx_info.nonce();
        let valid_nonce = if strict {
            account_nonce == incoming_tx_nonce
        } else {
            account_nonce <= incoming_tx_nonce
        };
        if valid_nonce {
            return Ok(state.increment_nonce(address)?);
        }
        Err(TransactionPreValidationError::InvalidNonce {
            address,
            account_nonce,
            incoming_tx_nonce,
        })
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L31-54)
```rust
impl StatelessTransactionValidator {
    #[instrument(skip(self), level = Level::INFO)]
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
    }
```
