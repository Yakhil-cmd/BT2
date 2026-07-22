### Title
Invoke Signature Validation Bypassed via Proxy Mempool Check in `skip_stateful_validations` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function uses `account_tx_in_pool_or_recent_block` as a proxy to infer that a `deploy_account` transaction exists for a new account. This proxy check can be satisfied by any transaction in the mempool from that address — including a legitimate `deploy_account` submitted by a different party. An attacker who observes a pending `deploy_account` in the mempool can immediately submit an invoke with `nonce=1` from the same address carrying an invalid signature. The gateway skips the `__validate__` entry-point call entirely, admitting the invalid transaction to the mempool without signature verification.

---

### Finding Description

In `extract_state_nonce_and_run_validations`, after nonce and resource-bound checks pass, the gateway calls `run_pre_validation_checks`, which calls `skip_stateful_validations`: [1](#0-0) 

The function returns `true` (skip `__validate__`) when:
- The transaction is an `Invoke`
- `tx.nonce() == Nonce(Felt::ONE)`
- `account_nonce == Nonce(Felt::ZERO)`
- `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

The mempool's implementation of `account_tx_in_pool_or_recent_block` returns `true` if **any** transaction from that address is in the pool or recent-block state — not specifically a `deploy_account`: [2](#0-1) 

When `skip_validate = true`, the gateway sets `validate: false` in `ExecutionFlags` and returns without calling the account's `__validate__` entry point: [3](#0-2) 

The `validate_by_mempool` call that precedes this only checks nonce ordering — it does not verify the signature: [4](#0-3) 

**Attack scenario:**

1. A legitimate user broadcasts a `deploy_account` for address `A` (deterministically computed from class hash, salt, constructor calldata — all visible in the mempool).
2. An attacker observes this `deploy_account` in the mempool and computes address `A`.
3. The attacker submits an `Invoke` with `nonce=1`, `sender_address=A`, and an **arbitrary/invalid signature**.
4. Gateway nonce check: `account_nonce=0 ≤ tx_nonce=1 ≤ max_allowed_nonce_gap` — passes.
5. `validate_by_mempool`: checks nonce ordering only — passes.
6. `skip_stateful_validations`: `tx_nonce=1`, `account_nonce=0`, `account_tx_in_pool_or_recent_block(A)=true` (due to the legitimate `deploy_account`) → returns `true`.
7. `run_validate_entry_point` is called with `validate=false` → `__validate__` is **never called**.
8. The invalid invoke is forwarded to the mempool and accepted.

This is the direct analog of the ENS `NameWrapper` bug: `ens.owner(node) != address(this)` was used as a proxy for "is this node wrapped?" and could be satisfied without the actual condition holding. Here, `account_tx_in_pool_or_recent_block` is used as a proxy for "does a `deploy_account` exist for this sender?" and can be satisfied by a third party's legitimate `deploy_account`, allowing the attacker's invoke to bypass signature validation.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway admits an invoke transaction with an invalid signature to the mempool. The transaction will fail during blockifier execution (the batcher runs `__validate__` unconditionally), but the mempool has already accepted it. This enables:
- Targeted mempool pollution for any address with a pending `deploy_account`
- Wasted batcher execution resources on guaranteed-revert transactions
- Potential griefing of the legitimate user's UX flow (e.g., nonce slot occupation)

---

### Likelihood Explanation

**Medium.** The attacker must monitor the public mempool for `deploy_account` transactions, compute the target address (deterministic and public), and race to submit the malicious invoke before the `deploy_account` is committed. No privileged access is required. The attack window is the time between `deploy_account` mempool admission and block commitment.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` proxy with a check that specifically verifies a `deploy_account` transaction exists in the mempool for the sender address. The mempool should expose a dedicated `has_pending_deploy_account(address)` query, or the existing check should be narrowed to only match `deploy_account` transaction types. This closes the gap between the proxy condition (any tx in pool) and the intended condition (a `deploy_account` in pool).

---

### Proof of Concept

```
1. Legitimate user submits:
     deploy_account { class_hash=C, salt=S, constructor_calldata=D, nonce=0, sig=valid }
     → address A = hash(C, S, D) is now in mempool

2. Attacker computes A from the visible deploy_account fields.

3. Attacker submits:
     invoke { sender_address=A, nonce=1, calldata=<anything>, sig=0xdeadbeef }

4. Gateway stateful validation:
     account_nonce(A) = 0  (not yet deployed)
     tx_nonce = 1
     validate_nonce: 0 ≤ 1 ≤ max_allowed_nonce_gap  → OK
     validate_by_mempool: nonce ordering check only   → OK
     skip_stateful_validations:
       tx_nonce==1 && account_nonce==0 → check mempool
       account_tx_in_pool_or_recent_block(A) → true (legitimate deploy_account)
       → returns true (SKIP __validate__)

5. run_validate_entry_point called with validate=false → no __validate__ call.

6. Attacker's invoke with sig=0xdeadbeef is forwarded to mempool and accepted.
``` [5](#0-4) [6](#0-5)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-355)
```rust
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
}
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-458)
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
