### Title
Gateway Skips `__validate__` Signature Check for Invoke Transactions with Nonce=1 When Deploy-Account Is Pending, Admitting Unsigned Transactions to Mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway stateful validator unconditionally bypasses the account contract's `__validate__` entry point for any Invoke transaction with `nonce=1` targeting an address that has a pending deploy-account transaction (or recently committed one). An unprivileged attacker can exploit this to inject an Invoke transaction with a garbage signature into the mempool. When the batcher later executes the transaction, `__validate__` is called, fails, and the victim's account is charged a fee for the failed validation.

---

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the function `skip_stateful_validations` returns `true` (skip `__validate__`) when all three conditions hold:

1. The transaction is an `Invoke`.
2. The transaction nonce equals `Felt::ONE`.
3. The on-chain account nonce is `Felt::ZERO` (account not yet deployed).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: !skip_validate = false`, so the blockifier's `StatefulValidator::perform_validations` path for Invoke transactions skips the `__validate__` call entirely at gateway admission time: [2](#0-1) 

The `account_tx_in_pool_or_recent_block` check is satisfied by any address that has ever had a transaction in the mempool or in a recently committed block: [3](#0-2) 

**Attack path:**

1. Attacker observes victim's `deploy_account` transaction in the mempool for address `A` (address is deterministic and publicly computable from the deploy-account calldata).
2. Attacker submits an Invoke transaction for address `A` with `nonce=1` and a garbage `signature`.
3. Gateway stateful validator: `account_nonce=0`, `tx_nonce=1`, `account_tx_in_pool_or_recent_block(A)=true` → `skip_validate=true` → transaction admitted to mempool **without** running `__validate__`.
4. Batcher pulls the transaction and executes it with `validate=true` (default for sequencing). `__validate__` is called, fails with `INVALID_SIGNATURE`, transaction reverts.
5. The fee for the failed validation gas is charged from the victim's pre-funded contract address.

The `perform_pre_validation_stage` in the blockifier (called during actual execution) does not re-check the signature — it only handles nonce, fee bounds, and proof facts: [4](#0-3) 

The `StatefulValidator::perform_validations` for Invoke calls `__validate__` only when `tx.execution_flags.validate` is `true`, which is set by the batcher (not the gateway): [5](#0-4) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An unprivileged attacker can inject an Invoke transaction with an arbitrary (invalid) signature into the mempool for any account that has a pending deploy-account. The transaction is admitted without signature verification. During execution, `__validate__` fails and the victim's pre-funded account balance is debited for the validation fee. The attacker pays nothing (the fee is charged to the victim's account, not the attacker's).

The broken invariant: *every Invoke transaction admitted to the mempool must have passed the account contract's `__validate__` signature check.*

---

### Likelihood Explanation

- The attack requires only that the victim's deploy-account transaction is visible in the mempool (or in a recent block), which is public information.
- The attacker needs no special privileges, no funds, and no knowledge of the victim's private key.
- The attack window is the period between the deploy-account entering the mempool and the account nonce advancing past 0 on-chain.
- The `account_tx_in_pool_or_recent_block` check also returns `true` for accounts in recently committed blocks, extending the window.

---

### Recommendation

Before skipping `__validate__`, verify that the Invoke transaction's signature is structurally valid (e.g., non-empty and of expected length), or alternatively, do not skip `__validate__` entirely — instead, run it speculatively against a state that includes the pending deploy-account's effect. If the UX skip must be preserved, at minimum document that the admitted transaction may carry an invalid signature and ensure the fee-charging path on revert cannot drain the victim's balance beyond a bounded amount.

Additionally, the `max_nonce_for_validation_skip` field in `StatefulTransactionValidatorConfig` is never consulted by `skip_stateful_validations` in the gateway path (it hardcodes `Nonce(Felt::ONE)`), making the config field a dead parameter: [6](#0-5) 

---

### Proof of Concept

```
1. Victim pre-funds address A = compute_contract_address(class_hash, salt, constructor_calldata).
2. Victim submits deploy_account tx for address A (nonce=0). It enters the mempool.
3. Attacker submits:
     Invoke {
       sender_address: A,
       nonce: 1,
       signature: [0xdead, 0xbeef],   // garbage
       calldata: [...],
       resource_bounds: { l2_gas: { max_amount: 1_000_000, max_price: 1 } },
       ...
     }
4. Gateway stateful validator:
     account_nonce = get_nonce_from_state(A) = 0   (not deployed yet)
     validate_nonce: 0 <= 1 <= 200  ✓
     validate_by_mempool: ok
     skip_stateful_validations:
       tx.nonce() == 1  ✓
       account_nonce == 0  ✓
       account_tx_in_pool_or_recent_block(A) == true  ✓  (deploy_account is in pool)
       → returns true (skip __validate__)
     run_validate_entry_point: validate=false → __validate__ NOT called
     → Invoke admitted to mempool.
5. Batcher executes block:
     deploy_account executes → A is deployed, nonce becomes 1.
     Invoke executes with validate=true:
       __validate__ called → INVALID_SIGNATURE → revert.
       Fee charged from A's balance for validation gas used.
```

### Citations

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-96)
```rust
    pub fn perform_validations(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        // Deploy account transaction should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        // Declare transaction should also be fully executed - otherwise, if we only go through
        // the validate phase, we would miss the check that the class was not declared before.
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
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L283-295)
```rust
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
```
