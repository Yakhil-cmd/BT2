### Title
Signature Validation Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Admission for Newly Deployed Accounts — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point check for any Invoke transaction with `nonce = 1` when the sender address appears in the mempool. The mempool presence check (`account_tx_in_pool_or_recent_block`) only confirms that *some* transaction from that address exists in the pool or a recent block — it does **not** verify that the incoming invoke is legitimately signed by the account owner. An unprivileged attacker who observes a victim's pending `deploy_account` transaction in the mempool can submit an unsigned/invalid invoke transaction on behalf of the victim, and the gateway will admit it without ever calling `__validate__`.

---

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which in turn calls `skip_stateful_validations`:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (nonce range, resource bounds)
       ├─ validate_by_mempool            (duplicate hash, nonce-too-old only)
       └─ skip_stateful_validations      ← broken guard
```

`skip_stateful_validations` returns `true` (skip `__validate__`) when all three conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)` (hardcoded).
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())` returns `true`. [1](#0-0) 

Condition 4 is satisfied whenever the victim's address has *any* transaction in the mempool pool or committed state: [2](#0-1) 

`MempoolState::contains_account` checks only the `staged` and `committed` maps — no signature check: [3](#0-2) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `skip_validate = true`, which sets `execution_flags.validate = false` and therefore never invokes the account's `__validate__` Cairo entry point: [4](#0-3) 

The preceding `validate_by_mempool` call only checks for duplicate transaction hashes and stale nonces — it performs no signature verification: [5](#0-4) 

The stateless validator checks only signature *length*, not validity: [6](#0-5) 

---

### Impact Explanation

An attacker can submit an invoke transaction with:
- `sender_address` = victim's address (attacker-controlled field)
- `nonce` = 1
- Arbitrary calldata
- Empty or forged signature

The gateway admits this transaction to the mempool without calling `__validate__`. Once in the mempool, the batcher will execute it. During execution the blockifier *does* call `__validate__`, so for standard accounts the transaction reverts — but:

1. **Nonce consumption (DoS)**: In Starknet, even reverted transactions increment the account nonce. The victim's nonce=1 is permanently consumed; the victim's legitimate first invoke (also nonce=1) is rejected as `NonceTooOld`. The victim must resubmit with nonce=2.
2. **Fee drain**: The victim's account is charged fees for the attacker's reverted transaction.
3. **Arbitrary execution against weak accounts**: For accounts that skip signature checks in `__validate__` (e.g., `AccountWithoutValidations` used in integration tests), the attacker's calldata executes unconditionally.

This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The attack requires only that the victim has a pending `deploy_account` transaction visible in the mempool. The mempool is observable by any network participant. The attacker needs no special privileges, no tokens, and no prior relationship with the victim. The window of vulnerability is the time between the victim's `deploy_account` entering the mempool and being committed on-chain (typically one block). During that window, any attacker can front-run with an invalid nonce=1 invoke.

---

### Recommendation

Replace the mempool-presence check with a check that verifies the incoming invoke transaction is signed by the account owner. The simplest fix mirrors the comment's stated intent: only skip `__validate__` when the *deploy_account* transaction for this exact sender address is in the mempool, not merely any transaction. Concretely:

```rust
// Instead of:
return mempool_client
    .account_tx_in_pool_or_recent_block(tx.sender_address())
    .await ...

// Require a deploy_account specifically:
return mempool_client
    .has_pending_deploy_account(tx.sender_address())
    .await ...
```

Alternatively, require the invoke transaction to carry a valid signature even in the skip-validate path (run `__validate__` but do not charge fee for the validation call), or require the invoke and deploy_account to be submitted atomically in a single multicall bundle so the gateway can verify both together.

Additionally, the `max_nonce_for_validation_skip` config field exists in `StatefulTransactionValidatorConfig` but is **not used** by the Rust gateway's `skip_stateful_validations` (it is only used in `PyValidator`). The nonce=1 threshold is hardcoded. This should be unified and the config field should govern the Rust path as well. [7](#0-6) 

---

### Proof of Concept

**Setup**: Victim `V` submits a `deploy_account` transaction (nonce=0) to the gateway. It is admitted and sits in the mempool.

**Attack**:
```
1. Attacker observes mempool: account_tx_in_pool_or_recent_block(V) == true
2. Attacker crafts:
     RpcInvokeTransactionV3 {
         sender_address: V,
         nonce: 1,
         calldata: [transfer_all_to_attacker],
         signature: [],   // empty / invalid
         resource_bounds: <valid>,
         ...
     }
3. Attacker submits to gateway.
4. Gateway path:
     stateless_validator.validate(&tx)          → OK (signature length 0 ≤ max)
     convert_rpc_tx_to_internal(tx)             → OK (hash computed, no sig check)
     extract_state_nonce_and_run_validations:
       account_nonce = get_nonce(V) = 0         → OK
       validate_state_preconditions             → OK (nonce 1 in [0, 200])
       validate_by_mempool                      → OK (no dup, nonce ≥ 0)
       skip_stateful_validations:
         tx.nonce() == 1 ✓
         account_nonce == 0 ✓
         account_tx_in_pool_or_recent_block(V) == true ✓
         → returns true (SKIP __validate__)
       run_validate_entry_point(skip=true)      → __validate__ NOT called
5. Transaction admitted to mempool.
6. Batcher executes block:
     deploy_account(V, nonce=0) → V deployed, nonce → 1
     attacker_invoke(V, nonce=1) → __validate__ called → reverts (bad sig)
                                    but nonce → 2, fee charged to V
7. Victim's legitimate invoke(V, nonce=1) → rejected: NonceTooOld
``` [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L702-711)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        if self.tx_pool.get_by_tx_hash(tx_reference.tx_hash).is_ok() {
            return Err(MempoolError::DuplicateTransaction { tx_hash: tx_reference.tx_hash });
        }
        self.state.validate_incoming_tx(tx_reference, incoming_account_nonce)
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

**File:** crates/apollo_gateway_config/src/config.rs (L283-283)
```rust
    pub max_nonce_for_validation_skip: Nonce,
```
