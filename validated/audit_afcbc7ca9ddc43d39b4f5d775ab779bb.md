### Title
`skip_stateful_validations` Bypasses `__validate__` Signature Check for Nonce-1 Invoke Transactions When Any Account Transaction Is in the Mempool — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry-point call (the account's on-chain signature verification) for any Invoke transaction with `nonce == 1` sent to an account whose on-chain nonce is still `0`, provided `account_tx_in_pool_or_recent_block` returns `true`. Because that check returns `true` for **any** transaction in the pool for that address — not only a `DeployAccount` — an unprivileged attacker can inject an Invoke transaction carrying an arbitrary, invalid signature into the mempool for any victim account that has a pending `DeployAccount`. The invalid transaction is admitted to the mempool without signature verification, blocks or displaces the victim's legitimate nonce-1 Invoke, and fails only later during batcher execution.

### Finding Description

**Relevant code path**

`extract_state_nonce_and_run_validations` (gateway stateful path) calls `run_pre_validation_checks`, which calls `skip_stateful_validations`, and then passes the result to `run_validate_entry_point`: [1](#0-0) 

`run_validate_entry_point` sets `execution_flags.validate = !skip_validate`: [2](#0-1) 

`skip_stateful_validations` returns `true` (skip) when:
- the transaction is an `Invoke` with `nonce == 1`,
- the on-chain account nonce is `0`, and
- `account_tx_in_pool_or_recent_block` returns `true`: [3](#0-2) 

`account_tx_in_pool_or_recent_block` returns `true` if **any** transaction for the address is in the pool — it does not distinguish `DeployAccount` from `Invoke`: [4](#0-3) 

When `execution_flags.validate == false`, `StatefulValidator::perform_validations` returns `Ok(())` immediately for Invoke transactions, never calling `__validate__`: [5](#0-4) 

And `validate_tx` in `AccountTransaction` also short-circuits: [6](#0-5) 

**Attack scenario (no fee escalation required)**

1. Victim V submits a `DeployAccount` (nonce 0). It passes full gateway validation and enters the mempool pool.
2. Attacker observes V's address in the mempool (public information) and immediately submits an `Invoke` for V with `nonce = 1` and an **arbitrary, invalid signature**.
3. Gateway `validate_by_mempool` succeeds — no existing nonce-1 entry for V, so `validate_fee_escalation` returns `Ok(None)`.
4. Gateway `skip_stateful_validations` queries `account_tx_in_pool_or_recent_block(V)` → `true` (V's `DeployAccount` is in the pool) → returns `true`.
5. `run_validate_entry_point` sets `validate = false`; `__validate__` is **never called**; the attacker's Invoke is admitted to the mempool.
6. V's `DeployAccount` executes in the batcher; V's on-chain nonce becomes 1.
7. V now tries to submit a legitimate nonce-1 Invoke. The mempool rejects it with `DuplicateNonce` (or requires fee escalation to displace the attacker's entry).
8. The attacker's Invoke is eventually pulled by the batcher, `__validate__` is called during execution, it fails (invalid signature), and the transaction is rejected — but V's legitimate transaction has already been blocked or lost.

**Fee-escalation variant (when `enable_fee_escalation = true`)**

If V has already submitted both `DeployAccount` and a legitimate nonce-1 Invoke, the attacker can additionally use fee escalation to replace V's legitimate Invoke with an invalid one: [7](#0-6) 

`validate_tx` accepts the replacement if tip and `max_l2_gas_price` are each increased by at least `fee_escalation_percentage`. Because `skip_stateful_validations` is evaluated after `validate_by_mempool` (which only checks fee levels, not signatures), the replacement bypasses `__validate__` in the same way. [8](#0-7) 

### Impact Explanation

An unprivileged attacker can inject an invalid (arbitrarily-signed) Invoke transaction into the mempool for **any** account that has a pending `DeployAccount`. The invalid transaction occupies the nonce-1 slot, blocking or displacing the victim's legitimate Invoke. The batcher will eventually reject the invalid transaction, but the victim's transaction is lost and must be resubmitted (potentially repeatedly if the attacker keeps front-running). This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The `DeployAccount` + nonce-1 Invoke UX flow is the documented, intended use case for `skip_stateful_validations` and is exercised in integration tests. Any account going through first-time deployment is vulnerable during the window between `DeployAccount` submission and its on-chain commitment. The attacker needs only the victim's address (observable from the mempool or the HTTP submission endpoint) and the ability to submit a transaction with a higher fee. No privileged access is required.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that is specific to `DeployAccount` transactions. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address) -> bool` that returns `true` only when a `DeployAccount` transaction (not any transaction) is present for the address. This closes the window where an attacker can exploit the presence of a non-`DeployAccount` transaction (or their own injected transaction) to bypass `__validate__`.

Alternatively, the gateway can perform a lightweight stateless check: read the account's class hash from state; if it is non-zero the account is already deployed and the skip should not apply; if it is zero, only skip validation when a `DeployAccount` is confirmed to be in the pool.

### Proof of Concept

```
# Step 1 – Victim submits DeployAccount for address V (nonce 0).
POST /add_transaction
{ "type": "DEPLOY_ACCOUNT", "sender_address": V, "nonce": "0x0",
  "signature": [<valid sig>], ... }
# → Accepted; V's DeployAccount enters the mempool pool.

# Step 2 – Attacker submits Invoke for V with nonce 1 and garbage signature.
POST /add_transaction
{ "type": "INVOKE", "sender_address": V, "nonce": "0x1",
  "signature": ["0xdeadbeef", "0xdeadbeef"],   # arbitrary invalid signature
  "calldata": [...], "tip": <higher than victim's>, ... }

# Gateway flow:
#   validate_by_mempool  → Ok(())   (no existing nonce-1 for V)
#   skip_stateful_validations
#     account_tx_in_pool_or_recent_block(V) → true  (DeployAccount is in pool)
#     → returns true
#   run_validate_entry_point(skip_validate=true)
#     execution_flags.validate = false
#     StatefulValidator::perform_validations → returns Ok(()) immediately
#     __validate__ is NEVER called
#   mempool.add_tx → attacker's Invoke admitted with nonce 1

# Step 3 – Victim tries to submit their legitimate nonce-1 Invoke.
POST /add_transaction
{ "type": "INVOKE", "sender_address": V, "nonce": "0x1",
  "signature": [<valid sig>], ... }
# → Rejected: MempoolError::DuplicateNonce (or requires fee escalation)

# Step 4 – Batcher pulls attacker's Invoke, calls __validate__, fails.
# Victim's transaction is lost.
``` [3](#0-2) [9](#0-8) [10](#0-9) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L760-791)
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
