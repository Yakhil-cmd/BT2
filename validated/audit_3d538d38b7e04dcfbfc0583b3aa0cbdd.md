### Title
`skip_stateful_validations` Admits Unsigned Invoke Transactions for Any Account With a Pending Mempool Entry — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function uses an overly broad membership check (`account_tx_in_pool_or_recent_block`) to decide whether to skip the `__validate__` entry-point call for an invoke transaction with `nonce == 1`. Because the check accepts *any* pooled transaction from the sender — not exclusively a `deploy_account` — an unprivileged attacker can submit an invoke with an arbitrary (invalid) signature on behalf of any account that already has a pending transaction in the mempool, and the gateway will admit it without running the account's signature-verification logic.

---

### Finding Description

The UX feature is documented in the code:

> "Check if validation of an invoke transaction should be skipped due to deploy_account not being processed yet."

The trigger condition is:

```
tx.nonce() == Nonce(Felt::ONE)  &&  account_nonce == Nonce(Felt::ZERO)
```

When both are true, the gateway calls `account_tx_in_pool_or_recent_block` and, if it returns `true`, sets `skip_validate = true`, which propagates into `execution_flags.validate = false` for the blockifier call. [1](#0-0) 

The mempool implementation of `account_tx_in_pool_or_recent_block` returns `true` whenever the address appears in the pool **or** in the committed-block state — regardless of transaction type:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

The code comment claims this is safe because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." The second branch is the flaw: an ordinary `invoke(nonce=0)` from an existing account (on-chain nonce = 0) also satisfies the check, yet it is not a `deploy_account`. Once that invoke is in the pool, the bypass fires for any subsequent `invoke(nonce=1)` submitted by *anyone*, because the gateway never verifies who is submitting the second transaction.

When `skip_validate = true` is returned, `run_validate_entry_point` sets `execution_flags.validate = false` and calls `blockifier_validator.validate(account_tx)`. Inside `StatefulValidator::perform_validations`, the `if !tx.execution_flags.validate { return Ok(()); }` guard exits before the `__validate__` entry-point call: [3](#0-2) [4](#0-3) 

The mempool's own `validate_tx` path checks nonce range and fee escalation but never inspects the cryptographic signature: [5](#0-4) 

---

### Impact Explanation

**Matching impact:** *High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.*

An attacker can inject an `invoke(nonce=1)` with a zeroed or fabricated signature for any victim account whose `invoke(nonce=0)` is currently pending. The gateway admits the transaction without running `__validate__`. The attacker can then exploit fee-escalation to continuously replace the victim's legitimate `nonce=1` transaction with their own invalid one. Because Starknet rejects (rather than reverts) transactions that fail `__validate__`, the attacker is **never charged a fee** for the invalid transactions, making the griefing economically free and repeatable.

---

### Likelihood Explanation

Mempool contents are observable by any network participant. Any account that has just been deployed or has never sent a transaction (on-chain nonce = 0) and has a pending transaction is a valid target. No privileged access, special contract, or large capital is required.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction for the sender address is present in the pool. For example, expose a `deploy_account_in_pool(address)` query on the mempool and use it exclusively in `skip_stateful_validations`. This preserves the intended UX (deploy + invoke in one batch) while closing the bypass for accounts that have only ordinary invoke transactions pending.

---

### Proof of Concept

1. **Setup.** Alice's account exists on-chain with `nonce = 0`.
2. **Step 1.** Alice submits `invoke(nonce=0)` with a valid signature. The gateway runs full validation including `__validate__`; the transaction enters the mempool. `account_tx_in_pool_or_recent_block(Alice) == true`.
3. **Step 2.** Bob (attacker) constructs `invoke(nonce=1, sender=Alice, calldata=<anything>, signature=[0,0])`. Bob submits it to the gateway.
4. **Gateway path.** `extract_state_nonce_and_run_validations` reads `account_nonce = 0`. `run_pre_validation_checks` calls `skip_stateful_validations`: `tx.nonce() == 1 && account_nonce == 0 && account_tx_in_pool_or_recent_block(Alice) == true` → returns `true`. `run_validate_entry_point` is called with `validate = false`; `__validate__` is never invoked. The transaction is admitted to the mempool.
5. **Fee escalation.** Bob sets a fee higher than Alice's pending `nonce=1` transaction. The mempool replaces Alice's valid transaction with Bob's invalid one.
6. **Execution.** The batcher executes Alice's `nonce=0` invoke (succeeds, nonce advances to 1). Bob's `nonce=1` invoke is executed with `validate = true` (batcher always validates); `__validate__` fails → transaction **rejected**, nonce stays at 1, **no fee charged to Bob**.
7. **Repeat.** Bob immediately submits a new `invoke(nonce=1, sender=Alice, signature=[0,0])` with an even higher fee, replacing Alice's next attempt. This loop continues indefinitely at zero cost to Bob. [6](#0-5) [2](#0-1) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-355)
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
