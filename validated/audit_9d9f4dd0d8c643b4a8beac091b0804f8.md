### Title
Signature-Skipping Bypass via `skip_stateful_validations` Admits Unsigned Invoke Transactions — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point call (the only place where a Starknet account verifies its own signature) for any `Invoke` transaction with `nonce=1` when the sender's on-chain nonce is `0` and `account_tx_in_pool_or_recent_block` returns `true`. The check is intended to confirm that a `deploy_account` transaction is pending, but it accepts **any** transaction type from that address. An unprivileged attacker who observes a victim's `deploy_account` in the mempool can submit an `Invoke(nonce=1)` with an arbitrary/fake signature for the victim's address; the gateway admits it without ever calling `__validate__`, violating the invariant that every admitted transaction carries a verified signature.

---

### Finding Description

**Root cause — `skip_stateful_validations` over-trusts `account_tx_in_pool_or_recent_block`** [1](#0-0) 

The function returns `true` (skip validation) when all three conditions hold:

1. The incoming transaction is `Invoke` with `nonce == 1`.
2. The on-chain account nonce is `0` (account not yet deployed).
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

The inline comment claims this is safe because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." That reasoning is only correct if the only way to get a transaction from a nonce-0 address into the mempool is via a fully-validated `deploy_account`. However, the check itself is the bypass: once the victim's legitimate `deploy_account` is in the mempool, condition 3 is satisfied for **any** `Invoke(nonce=1)` submitted for that address, regardless of its signature. [2](#0-1) 

**How `skip_validate=true` suppresses signature verification**

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, so the blockifier's `StatefulValidator` returns immediately without calling `validate_tx` (i.e., `__validate__`): [3](#0-2) [4](#0-3) 

The stateless validator only checks signature **length**, not cryptographic validity: [5](#0-4) 

No other gateway-level check verifies the signature. The transaction is forwarded to the mempool with an unverified signature.

**`account_tx_in_pool_or_recent_block` does not distinguish transaction types** [6](#0-5) 

It returns `true` for any transaction type (deploy_account, invoke, declare) from the address, and also for addresses seen in recent committed blocks.

**`validate_by_mempool` does not verify signatures**

The mempool's `validate_tx` only checks for duplicate hashes and nonce/fee-escalation rules — no signature check: [7](#0-6) 

---

### Impact Explanation

**Admission of invalid (unsigned) transactions — High**

An attacker can inject an `Invoke(nonce=1)` with an arbitrary signature for any victim address whose `deploy_account` is pending in the mempool. The gateway admits it without signature verification. When the batcher later executes it, `__validate__` is called and fails, causing the transaction to revert. In Starknet, a reverted transaction still charges a fee, so the victim's balance is debited for a transaction they never authorized.

Additionally, if the attacker submits the fake invoke with a tip higher than the victim's legitimate `Invoke(nonce=1)`, the mempool's fee-escalation logic replaces the victim's valid transaction with the attacker's fake one, permanently evicting the victim's first post-deployment call.

---

### Likelihood Explanation

The mempool is observable (P2P propagation, RPC). Any attacker watching for `deploy_account` transactions can immediately submit a competing `Invoke(nonce=1)` with a fake signature and a higher tip. No privileged access, special keys, or prior relationship with the victim is required. The window is the time between the victim's `deploy_account` entering the mempool and being committed to a block.

---

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a type-specific check that confirms a **`deploy_account`** transaction (not just any transaction) is pending for the address. For example, expose a `deploy_account_in_pool(address)` query from the mempool, or store the transaction type alongside the account state so the gateway can assert the pending transaction is a `deploy_account` before skipping `__validate__`.

Alternatively, never skip `__validate__` based solely on mempool state; instead, allow the `deploy_account` and `invoke` to be submitted together and defer the invoke's validation until after the deploy_account is committed (accepting the UX trade-off).

---

### Proof of Concept

1. Victim generates a new keypair for address `B` and submits `deploy_account(B)` to the gateway. The gateway fully executes `__validate_deploy__`, which passes. `deploy_account(B)` enters the mempool.

2. Attacker observes `deploy_account(B)` in the mempool (via P2P or RPC). Attacker constructs `Invoke(sender=B, nonce=1, calldata=<drain_calldata>, signature=<random_bytes>, tip=victim_tip+1)`.

3. Attacker submits the fake invoke to the gateway. The gateway evaluates:
   - Stateless: signature length is within bounds — **passes**.
   - Stateful nonce: `account_nonce=0 ≤ tx_nonce=1 ≤ max_allowed_nonce_gap` — **passes**.
   - `validate_by_mempool`: no duplicate hash, fee-escalation succeeds (higher tip) — **passes**.
   - `skip_stateful_validations`: `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(B)==true` → returns `true`.
   - `run_validate_entry_point`: `validate=false` → `__validate__` is **never called**.

4. The fake invoke is added to the mempool, replacing the victim's legitimate `Invoke(nonce=1)` via fee escalation.

5. Batcher sequences: `deploy_account(B)` executes and succeeds (nonce advances to 1). The fake `Invoke(nonce=1)` executes: `__validate__` is called, fails (bad signature), transaction reverts. Fee is charged from `B`'s balance.

6. The victim's legitimate invoke was evicted; the victim must resubmit at nonce 2 and has lost the fee for the attacker's reverted transaction.

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L142-150)
```rust
    fn validate_tx_size(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        self.validate_tx_extended_calldata_size(tx)?;
        self.validate_tx_signature_size(tx)?;
        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_proof_size(invoke_tx)?;
        }

        Ok(())
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
