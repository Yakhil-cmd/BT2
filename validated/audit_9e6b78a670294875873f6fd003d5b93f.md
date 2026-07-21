### Title
Unauthenticated invoke transaction with nonce=1 bypasses gateway signature validation via `skip_stateful_validations` when victim's deploy_account is in mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point call (i.e., signature verification) for any invoke transaction with `nonce == 1` submitted against an account whose on-chain nonce is still `0`, provided `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. Because that mempool check is satisfied the moment the **victim's own** `deploy_account` transaction enters the pool, an unprivileged attacker can immediately submit a forged invoke (nonce=1, arbitrary calldata, no valid signature) for the victim's address. The gateway accepts it without running `__validate__`, the mempool stores it, and the victim's legitimate nonce-1 invoke is blocked with `DuplicateNonce`. The attack is repeatable at negligible cost, creating a continuous griefing loop that prevents the victim from ever executing their first post-deployment transaction.

---

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

When this returns `true`, `run_validate_entry_point` sets `validate: false` in the `ExecutionFlags`, so the blockifier's `StatefulValidator::perform_validations` returns `Ok(())` without ever calling `__validate__`: [2](#0-1) 

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
// ...
blockifier_validator.validate(account_tx)  // __validate__ is skipped when validate=false
```

And in the blockifier's `StatefulValidator`: [3](#0-2) 

```rust
ApiTransaction::Invoke(_) => {
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    if !tx.execution_flags.validate {
        return Ok(());   // ← exits here; __validate__ never called
    }
    let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
    ...
}
```

**The mempool check is not ownership-gated**

`account_tx_in_pool_or_recent_block` returns `true` for any address that has *any* transaction in the pool or a recently committed block: [4](#0-3) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

The moment the victim's `deploy_account` transaction is accepted into the pool, `tx_pool.contains_account(victim_address)` becomes `true`. There is no check that the *incoming* invoke transaction originates from the same key-pair as the deploy_account.

**Gateway flow confirms the transaction is then forwarded to the mempool** [5](#0-4) 

```rust
let nonce = stateful_transaction_validator
    .extract_state_nonce_and_run_validations(&executable_tx, self.mempool_client.clone())
    .await?;
// ...
self.mempool_client.add_tx(add_tx_args).await;
```

After `extract_state_nonce_and_run_validations` returns `Ok` (with `__validate__` skipped), the transaction is unconditionally forwarded to the mempool.

**Mempool does not verify signatures**

The mempool's `validate_tx` only checks for duplicate hashes, nonce ordering, and fee escalation — no signature check: [6](#0-5) 

```rust
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
```

**Batcher execution path**

When the batcher eventually executes the attacker's invoke, it uses `new_for_sequencing` (confirmed in `crates/native_blockifier/src/py_transaction.rs` and the Apollo block-builder path), which always sets `validate: true`: [7](#0-6) 

```rust
pub fn new_for_sequencing(tx: Transaction) -> Self {
    let execution_flags = ExecutionFlags {
        only_query: false,
        charge_fee: enforce_fee(&tx, false),
        validate: true,
        strict_nonce_check: true,
    };
    AccountTransaction { tx, execution_flags }
}
```

`__validate__` is called, the forged signature fails, and the transaction is **rejected** (not reverted) — the nonce is **not** incremented. However, while the attacker's transaction occupies the nonce-1 slot in the mempool, the victim's legitimate invoke is rejected with `DuplicateNonce`. The attacker can re-submit immediately after each rejection.

---

### Impact Explanation

An unprivileged attacker can continuously block any account from executing its first post-deployment invoke transaction. The gateway admits an unsigned (forged) invoke transaction into the mempool, violating the invariant that every transaction in the mempool has passed signature verification. This matches:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

The victim's legitimate nonce-1 invoke is perpetually displaced from the mempool. The attacker pays only the gateway submission overhead (no on-chain fee, since the transaction is rejected before execution). The victim cannot progress past nonce 1 without the attacker's cooperation.

---

### Likelihood Explanation

- The victim's address is public (visible in the mempool as soon as `deploy_account` is submitted).
- The attacker needs only to craft an `InvokeV3` transaction with `sender_address = victim`, `nonce = 1`, arbitrary calldata, and any (invalid) signature.
- No privileged access, no special knowledge, and no on-chain cost is required.
- The attack window opens the moment the victim's `deploy_account` enters the mempool and remains open until the victim's nonce advances past 1 on-chain.

---

### Recommendation

The `skip_stateful_validations` function must not skip `__validate__` solely based on a mempool membership check. Possible mitigations:

1. **Remove the skip entirely at the gateway level.** Accept that the invoke with nonce=1 will fail gateway validation when the account is not yet deployed, and rely on the user to retry after the deploy_account is confirmed. This is the safest fix.

2. **Require the invoke to carry a structurally valid signature before skipping `__validate__`.** Even without a deployed contract, the gateway can verify that the signature is non-empty and well-formed, raising the cost of the attack.

3. **Scope the skip to transactions whose `tx_hash` was pre-registered by the same submitter** (e.g., require the deploy_account and the paired invoke to be submitted together in a single atomic RPC call, with the gateway binding them by sender identity).

---

### Proof of Concept

```
1. Victim submits RpcDeployAccountTransactionV3 for address V.
   → Gateway accepts it; mempool now has V in tx_pool.
   → account_tx_in_pool_or_recent_block(V) == true.

2. Attacker crafts RpcInvokeTransactionV3:
     sender_address = V
     nonce          = 1
     calldata       = [<arbitrary>]
     signature      = [0x0]   // invalid

3. Attacker submits to gateway.
   → stateless_tx_validator.validate: passes (non-empty resource bounds, valid address, etc.)
   → convert_rpc_tx_to_internal: succeeds (no signature check here)
   → extract_state_nonce_and_run_validations:
       account_nonce = 0  (V not yet deployed)
       validate_state_preconditions: nonce 1 within allowed gap → OK
       validate_by_mempool: no duplicate hash, nonce gap OK → OK
       skip_stateful_validations: nonce==1 && account_nonce==0
           && account_tx_in_pool_or_recent_block(V)==true → returns true
       run_validate_entry_point: validate=false → __validate__ NOT called → OK
   → mempool.add_tx: attacker's invoke stored at (V, nonce=1)

4. Victim submits their legitimate invoke (nonce=1, valid signature).
   → mempool.validate_tx: DuplicateNonce { address: V, nonce: 1 } → REJECTED

5. Batcher eventually executes attacker's invoke:
   → new_for_sequencing sets validate=true
   → __validate__ called → signature invalid → transaction REJECTED (nonce not incremented)

6. Attacker immediately repeats step 2–3. Loop continues indefinitely.
```

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L74-95)
```rust
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

**File:** crates/apollo_gateway/src/gateway.rs (L263-286)
```rust
        let nonce = stateful_transaction_validator
            .extract_state_nonce_and_run_validations(&executable_tx, self.mempool_client.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let proof_archive_handle = self
            .store_proof_and_spawn_archiving(proof_data, internal_tx.tx_hash, is_p2p)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let gateway_output = create_gateway_output(&internal_tx);

        let add_tx_args = AddTransactionArgsWrapper {
            args: AddTransactionArgs::new(internal_tx, nonce),
            p2p_message_metadata,
        };

        // Await as late as possible for proof archiving before sending the transaction to the
        // mempool.
        Self::await_proof_archiving(proof_archive_handle)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let mempool_client_result = self.mempool_client.add_tx(add_tx_args).await;
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```
