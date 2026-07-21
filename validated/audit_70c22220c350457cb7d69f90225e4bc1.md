### Title
Gateway `skip_stateful_validations` admits invoke transactions with invalid signatures when any account tx exists in mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway stateful validator skips the `__validate__` entry-point call (the only place where the account's signature is verified at the gateway level) for any invoke transaction with `nonce == 1` when the account's on-chain nonce is `0` and the account has **any** transaction in the mempool. The check is designed for the deploy-account + invoke UX, but the condition `account_tx_in_pool_or_recent_block` is satisfied by any transaction type in the pool, not only a `deploy_account`. An attacker with a deployed account whose on-chain nonce is still `0` can submit a valid nonce-0 invoke to seed the mempool, then immediately submit a nonce-1 invoke with a completely invalid signature; the gateway skips `__validate__` and admits the second transaction.

---

### Finding Description

**Invariant broken:** Every invoke transaction accepted by the gateway must have passed `__validate__` (signature verification) before entering the mempool.

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip) when:
1. The transaction is `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)` (on-chain state)
4. `account_tx_in_pool_or_recent_block(sender)` returns `true`

**`account_tx_in_pool_or_recent_block` is too broad:** [2](#0-1) 

It returns `true` if the account has **any** transaction in the pool (`tx_pool.contains_account`) — not specifically a `deploy_account`. A deployed account whose on-chain nonce is still `0` (e.g., deployed via `deploy_syscall` from a factory contract) satisfies condition 3 and can place any valid nonce-0 invoke in the pool to satisfy condition 4.

**Effect when skip is `true`:** [3](#0-2) 

`execution_flags.validate` is set to `false`. Inside `StatefulValidator::perform_validations`: [4](#0-3) 

The `__validate__` call is skipped entirely and the function returns `Ok(())`. The transaction is then forwarded to the mempool with no signature check ever having been performed.

**`validate_tx` also short-circuits on the same flag:** [5](#0-4) 

So even the blockifier-level call inside `run_validate_entry_point` is a no-op when `validate = false`.

**No other guard catches the signature.** `StatelessTransactionValidator::validate` performs no signature check: [6](#0-5) 

`validate_by_mempool` only checks nonce and fee bounds: [7](#0-6) 

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An invoke transaction carrying an arbitrary (attacker-chosen) invalid signature is admitted to the mempool. The gateway's admission invariant — that every accepted invoke has passed `__validate__` — is broken. The invalid transaction occupies a mempool slot, consumes batcher execution resources when dequeued, and will fail during block execution (causing a rejected-transaction event). Because the attacker controls the account and can ensure its balance is zero, the fee-charge on failure costs nothing; the attack can be repeated indefinitely at the cost of a single valid nonce-0 transaction per account.

---

### Likelihood Explanation

**Likelihood: Medium.**

The preconditions are:
- An account deployed via `deploy_syscall` (factory pattern) whose on-chain nonce is still `0`. This is a normal pattern for smart-wallet factories.
- `max_allowed_nonce_gap >= 1` in the gateway config (required for the deploy-account + invoke UX to function at all, so it is always set).
- The attacker submits a valid nonce-0 invoke first (one-time cost, gas only).

No privileged access is required. The attack is repeatable.

---

### Recommendation

1. **Narrow the skip condition to deploy-account presence only.** Instead of `account_tx_in_pool_or_recent_block`, introduce a dedicated `deploy_account_in_pool(address)` query that returns `true` only when a `deploy_account` transaction for that address is present in the pool. This preserves the UX intent while closing the loophole.

2. **Alternatively, add an on-chain class-hash check.** Before skipping `__validate__`, verify that `state.get_class_hash_at(sender) == ClassHash::default()` (i.e., the account contract does not yet exist on-chain). A deployed account with nonce `0` will have a non-zero class hash and must not skip validation.

---

### Proof of Concept

```
Preconditions:
  - Account A deployed via factory contract; on-chain class_hash ≠ 0, on-chain nonce = 0.
  - Gateway config: max_allowed_nonce_gap ≥ 1.

Step 1 — seed the mempool:
  Submit InvokeV3 from A, nonce=0, valid signature.
  → Gateway: validate_nonce passes (0 ≤ 0 ≤ gap), __validate__ called, signature OK.
  → Mempool: tx_pool.contains_account(A) = true.

Step 2 — submit invalid-signature invoke:
  Submit InvokeV3 from A, nonce=1, signature = [0xdeadbeef, ...] (garbage).

  Gateway stateful path:
    account_nonce = get_nonce_from_state(A) = 0          ← on-chain nonce still 0
    validate_nonce: 0 ≤ 1 ≤ max_allowed_nonce_gap        ← PASSES
    validate_by_mempool: nonce/fee check only             ← PASSES
    skip_stateful_validations:
      tx.nonce() == 1  ✓
      account_nonce == 0  ✓
      account_tx_in_pool_or_recent_block(A) == true  ✓   ← seeded in Step 1
      → returns true (SKIP)
    run_validate_entry_point(skip_validate=true):
      execution_flags.validate = false
      StatefulValidator::perform_validations → early return Ok(())
      __validate__ NEVER CALLED

  → Invalid-signature transaction admitted to mempool.

Step 3 — repeat Step 2 with fresh garbage signatures at zero net cost
  (keep account balance = 0 so fee-charge on execution failure is a no-op).
``` [8](#0-7) [2](#0-1) [9](#0-8)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L37-53)
```rust
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
```
