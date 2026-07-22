### Title
Unbound `skip_stateful_validations` Allows Unauthorized Invoke Admission Without Signature Verification — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` UX feature, designed to let a user submit an invoke at nonce 1 before their own `deploy_account` (nonce 0) is confirmed, does not bind the skip decision to the identity of the submitter. Any third party who observes a victim's `deploy_account` in the mempool can immediately submit an invoke transaction carrying the victim's `sender_address`, nonce 1, and an **arbitrary (invalid) signature**. The gateway will skip the blockifier `validate` entry-point call entirely, admitting the malformed transaction to the mempool without any signature check.

---

### Finding Description

`skip_stateful_validations` returns `true` — causing `run_validate_entry_point` to set `validate: false` and skip the account's `__validate__` entry point — whenever three conditions hold simultaneously:

1. The incoming transaction is an `Invoke` with `nonce == 1`.
2. The on-chain account nonce is `0` (account not yet deployed).
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

None of these three conditions is tied to *who submitted the transaction*. Condition 3 is satisfied by the **victim's** `deploy_account` that is already in the pool. An attacker who observes that `deploy_account` can craft an invoke with the victim's `sender_address`, `nonce = 1`, and a garbage signature; all three conditions will be true for the attacker's transaction, so `skip_validate = true`.

`run_validate_entry_point` then builds `ExecutionFlags { validate: !skip_validate, … }` and calls `blockifier_validator.validate(account_tx)`. When `validate = false`, `validate_tx` returns `Ok(None)` immediately without executing the account's `__validate__` entry point. [2](#0-1) 

The transaction then proceeds through `validate_by_mempool` (which checks nonce range and fee bounds, not the signature) and is forwarded to the mempool via `mempool_client.add_tx`. [3](#0-2) 

The analog to the NFT report is direct: in the NFT contract the signed whitelist code was not bound to the buyer's address, so any observer could reuse it. Here the skip-validation grant is not bound to the address that submitted the `deploy_account`, so any observer can exploit it for a different sender.

---

### Impact Explanation

**Matching impact tier: High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

Concrete consequences:

1. **Invalid transaction admitted to mempool.** A transaction whose signature has never been verified enters the mempool. This violates the invariant that every transaction in the mempool has passed account-level signature validation.

2. **Victim's legitimate invoke displaced or replaced.** If the victim also submits a valid invoke at nonce 1, the mempool now holds two transactions for the same (address, nonce) slot. Fee-escalation logic may evict the victim's valid transaction in favour of the attacker's invalid one.

3. **Fee charge on victim.** When the batcher later executes the block, the victim's `deploy_account` (nonce 0) runs first, deploying the account. The attacker's invoke (nonce 1) is then dequeued. `perform_pre_validation_stage` increments the nonce and — if `charge_fee = true` and the victim has sufficient balance — calls `verify_can_pay_committed_bounds` before invoking `__validate__`. The `__validate__` call fails (invalid signature), the transaction is rejected, and the victim is charged a fee for a transaction they never signed. [4](#0-3) 

---

### Likelihood Explanation

- **No privileged access required.** The attacker only needs to observe the mempool (public P2P gossip) to learn the victim's `sender_address` and confirm a `deploy_account` is pending.
- **Nonce 1 window is predictable.** The UX pattern of sending `deploy_account + invoke` together is explicitly documented and encouraged; the window is open from the moment the `deploy_account` enters the mempool until it is committed.
- **Trivial to craft.** The attacker constructs a standard `RpcInvokeTransactionV3` with the victim's address, `nonce = 1`, and any 1-element signature array (passes the stateless `max_signature_length` check). [5](#0-4) 

---

### Recommendation

Bind the skip-validation grant to the submitter's identity. The simplest fix is to require that the transaction's `sender_address` matches the address of the `deploy_account` transaction that the *same client* submitted in the same request batch, rather than relying solely on a mempool presence check. Alternatively, require that the invoke transaction carry a valid signature even when `skip_validate` would otherwise apply — the account class hash is known from the `deploy_account` constructor calldata, so the public key can be extracted and the signature verified off-chain before admission.

At minimum, `account_tx_in_pool_or_recent_block` should be narrowed to check specifically for a `deploy_account` transaction at nonce 0 from the same address, not any transaction type. [6](#0-5) 

---

### Proof of Concept

```
1. Victim submits DeployAccount for address A (nonce 0, valid signature).
   → deploy_account enters the mempool.

2. Attacker observes A in the mempool (P2P gossip / RPC).

3. Attacker submits:
     RpcInvokeTransactionV3 {
         sender_address: A,
         nonce: 1,
         signature: [0x1],   // arbitrary, never verified
         calldata: <drain A's balance>,
         resource_bounds: <valid>,
         ...
     }

4. Gateway stateless check passes (signature length ≤ max_signature_length).

5. convert_rpc_tx_to_internal computes tx_hash for (A, nonce=1, attacker calldata).

6. extract_state_nonce_and_run_validations:
     account_nonce = get_nonce_from_state(A) = 0   ✓ condition 2
     validate_nonce: 0 ≤ 1 ≤ max_gap              ✓ passes
     validate_by_mempool: nonce/fee check only      ✓ passes
     skip_stateful_validations:
       tx.nonce() == 1 && account_nonce == 0        ✓ condition 1+2
       account_tx_in_pool_or_recent_block(A) = true ✓ condition 3 (victim's deploy_account)
       → returns true (skip_validate = true)
     run_validate_entry_point(skip_validate=true):
       ExecutionFlags { validate: false, … }
       validate_tx returns Ok(None) immediately      ← signature NEVER checked

7. Attacker's invoke is forwarded to mempool.add_tx.

8. Batcher block:
     execute deploy_account(A, nonce=0)  → A deployed
     execute attacker's invoke(A, nonce=1):
       perform_pre_validation_stage: nonce incremented to 2
       __validate__ called → INVALID_SIGNATURE → tx rejected
       A charged fee for attacker's transaction.

9. Victim's legitimate invoke(A, nonce=1) now fails: nonce already at 2.
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L426-461)
```rust
/// Check if validation of an invoke transaction should be skipped due to deploy_account not being
/// processed yet. This feature is used to improve UX for users sending deploy_account + invoke at
/// once.
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
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
    }
```
