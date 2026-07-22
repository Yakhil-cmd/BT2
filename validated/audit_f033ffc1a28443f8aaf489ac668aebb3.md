### Title
`skip_stateful_validations` Admits Unsigned Invoke (nonce=1) by Conflating Any Mempool Entry with a deploy_account — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's UX shortcut for the deploy_account + invoke bundle pattern skips the `__validate__` entry-point check for any invoke with `tx_nonce == 1` when `account_nonce == 0`, provided `account_tx_in_pool_or_recent_block` returns `true`. That helper returns `true` for **any** transaction in the pool for the address, not exclusively a `deploy_account`. An unprivileged attacker who observes a victim's `deploy_account` in the public mempool can immediately submit an invoke with `nonce=1` carrying an arbitrary (invalid) signature, bypass `__validate__` at the gateway, and—because fee escalation is enabled by default—replace the victim's legitimate invoke in the mempool with a transaction that will be rejected during block execution.

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The condition at line 437 fires whenever `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)`. When it fires, the function delegates to: [2](#0-1) 

`account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in `tx_pool` or was seen in a recent committed block. It does not filter for `deploy_account` transactions. The comment in `skip_stateful_validations` acknowledges this imprecision ("either it has a deploy_account transaction **or** transactions with future nonces that passed validations"), but the second branch is unreachable for a brand-new account (nonce=0), and the first branch is exploitable by a third party.

**Effect on the validation pipeline:**

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, the `__validate__` call is gated on `execution_flags.validate`: [4](#0-3) 

`perform_pre_validation_stage` (nonce increment, fee-bound check, balance check) still runs, but the account's signature is never verified at admission time.

**Fee escalation enables replacement:**

Fee escalation is on by default (`enable_fee_escalation: true`, `fee_escalation_percentage: 10`): [5](#0-4) 

`validate_fee_escalation` / `add_tx_validations` will replace an existing `(address, nonce=1)` entry if the incoming transaction offers ≥10 % higher tip and max-L2-gas-price: [6](#0-5) 

### Impact Explanation

An attacker who monitors the public mempool for `deploy_account` transactions can, for every such transaction targeting address X:

1. Craft an invoke for address X with `nonce=1`, arbitrary calldata, an invalid signature, and a tip ≥10 % above the victim's pending invoke.
2. Submit it to the gateway. `skip_stateful_validations` returns `true` (the deploy_account is already in the pool), `__validate__` is skipped, `verify_can_pay_committed_bounds` passes (the account was pre-funded), and the transaction is forwarded to the mempool.
3. The mempool replaces the victim's legitimate invoke with the attacker's invalid one.
4. When the block is built, the deploy_account executes successfully, then the attacker's invoke is attempted; `__validate__` fails during execution and the transaction is rejected without charging a fee.
5. The victim's invoke is permanently lost from the mempool; the victim must resubmit.

This matches the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

### Likelihood Explanation

- The Starknet mempool is public; any observer can detect `deploy_account` transactions in real time.
- No privileged access, no private key knowledge, and no on-chain state is required.
- The attack window is the interval between the victim's `deploy_account` entering the mempool and the block being sealed—typically several seconds to minutes.
- Fee escalation is enabled by default, making replacement straightforward.
- The attacker bears no cost: the invalid invoke is rejected during execution without a fee charge.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a type-specific query that returns `true` only when a `deploy_account` transaction (or a committed deploy) exists for the address. Concretely:

1. Add a `deploy_account_in_pool_or_recent_block(address)` method to the mempool that inspects `InternalRpcTransactionWithoutTxHash::DeployAccount` entries.
2. In `skip_stateful_validations`, call this narrower predicate instead of the generic one.
3. Alternatively, restrict the skip to cases where the account's class hash is already set in state (i.e., the deploy_account was already executed), eliminating the race window entirely.

### Proof of Concept

```
Preconditions:
  - Victim controls address X (class_hash C, salt S, constructor_calldata D).
  - Victim pre-funds X with STRK.
  - Victim submits deploy_account(X) → enters mempool (passes __validate_deploy__).
  - Victim submits invoke(X, nonce=1, tip=T, valid_sig) → enters mempool.

Attack:
1. Attacker observes deploy_account(X) in the public mempool.
   → account_tx_in_pool_or_recent_block(X) now returns true.

2. Attacker submits:
     invoke(
       sender_address = X,
       nonce          = 1,
       calldata       = [arbitrary],
       signature      = [0x0, 0x0],   // invalid
       tip            = T * 1.11,     // exceeds 10% escalation threshold
       max_l2_gas_price = victim_price * 1.11
     )

3. Gateway stateless validation: passes (signature length ≤ max, resource bounds OK).

4. Gateway stateful validation:
   a. account_nonce = get_nonce(X) = 0.
   b. validate_nonce: 0 ≤ 1 ≤ max_gap → OK.
   c. validate_by_mempool: validate_fee_escalation passes (tip > victim's tip).
   d. skip_stateful_validations:
        tx.nonce() == 1 && account_nonce == 0 → check pool
        account_tx_in_pool_or_recent_block(X) == true  ← deploy_account is there
        → returns true (skip __validate__)
   e. run_validate_entry_point(skip_validate=true):
        execution_flags.validate = false
        perform_pre_validation_stage runs (nonce OK, fee bounds OK, balance OK)
        __validate__ is NOT called
        → returns Ok(())

5. mempool.add_tx: replaces victim's invoke with attacker's invalid invoke.

6. Block execution:
   - deploy_account(X) executes → X deployed.
   - attacker's invoke(X, nonce=1) executes → __validate__ called → FAILS.
   - Transaction rejected, no fee charged.

7. Victim's invoke is gone from the mempool; victim must resubmit.
``` [1](#0-0) [2](#0-1) [7](#0-6)

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

**File:** crates/apollo_mempool/src/mempool.rs (L760-792)
```rust
    fn validate_fee_escalation(
        &self,
        incoming_tx_reference: TransactionReference,
    ) -> MempoolResult<Option<TransactionReference>> {
        let TransactionReference { address, nonce, .. } = incoming_tx_reference;

        self.validate_no_delayed_declare_front_run(incoming_tx_reference)?;

        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
        }

        let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
        else {
            // Replacement irrelevant: no existing transaction with the same nonce for address.
            return Ok(None);
        };

        if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
            info!(
                "{existing_tx_reference} was not replaced by {incoming_tx_reference} due to \
                 insufficient fee escalation."
            );
            // TODO(Elin): consider adding a more specific error type / message.
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }

        Ok(Some(existing_tx_reference))
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

**File:** crates/apollo_mempool_config/src/config.rs (L85-99)
```rust
impl Default for MempoolStaticConfig {
    fn default() -> Self {
        Self {
            enable_fee_escalation: true,
            validate_resource_bounds: true,
            fee_escalation_percentage: 10,
            declare_delay: Duration::from_secs(1),
            committed_nonce_retention_block_count: 100,
            capacity_in_bytes: 1 << 30, // 1GB.
            behavior_mode: BehaviorMode::Starknet,
            recorder_url: "https://recorder_url"
                .parse::<Url>()
                .expect("recorder_url must be a valid Recorder URL"),
        }
    }
```
