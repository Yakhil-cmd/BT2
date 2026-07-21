Now I have the complete picture. Let me trace the full attack chain through all layers.

**Critical finding:** Both state readers use the **same** `latest_block_number` and **both** silently swallow `ContractNotFound` by returning zero defaults:

---

### Title
Stale-Block `ContractNotFound` → `Nonce::default()` Silencing in Both State Readers Allows Duplicate `DeployAccount` Admission — (`crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs`)

---

### Summary

Both the gateway-level nonce reader (`GatewayFixedBlockSyncStateClient`) and the blockifier-level state reader (`SyncStateReader`) are created from the **same** `latest_block_number` snapshot and **both** silently convert `StateSyncError::ContractNotFound` into zero defaults (`Nonce::default()`, `ClassHash::default()`). During the window between a block being committed and state sync updating, an already-deployed account appears undeployed to every layer of validation, allowing a duplicate `DeployAccount` transaction to pass all gateway and blockifier checks and be admitted to the mempool.

---

### Finding Description

**Layer 1 — Gateway nonce check (`GatewayFixedBlockSyncStateClient::get_nonce`):**

`ContractNotFound` is silently mapped to `Nonce::default()`:

```rust
Err(StateSyncClientError::StateSyncError(StateSyncError::ContractNotFound(_))) => {
    Ok(Nonce::default())
}
``` [1](#0-0) 

`validate_nonce` for `DeployAccount` only rejects if `account_nonce != Nonce(Felt::ZERO)`. With `account_nonce == 0` (from the above), the check passes:

```rust
ExecutableTransaction::DeployAccount(_) => {
    if account_nonce != Nonce(Felt::ZERO) {
        return Err(...); // NOT reached
    }
``` [2](#0-1) 

**Layer 2 — Blockifier state reader (`SyncStateReader`) uses the same stale block:**

`SyncStateReaderFactory::get_blockifier_state_reader_and_gateway_fixed_block_from_latest_block` calls `get_latest_block_number()` **once** and passes the result to **both** readers:

```rust
let latest_block_number = self.shared_state_sync_client.get_latest_block_number().await?;
let blockifier_state_reader = SyncStateReader::from_number(..., latest_block_number, ...);
let gateway_fixed_block_sync_state_client =
    GatewayFixedBlockSyncStateClient::new(..., latest_block_number);
``` [3](#0-2) 

`SyncStateReader::get_nonce_at` **also** maps `ContractNotFound` → `Nonce::default()`: [4](#0-3) 

`SyncStateReader::get_class_hash_at` **also** maps `ContractNotFound` → `ClassHash::default()` (zero = undeployed): [5](#0-4) 

**Layer 3 — State sync `get_nonce_at` returns `ContractNotFound` for any address not deployed at the queried block:**

```rust
verify_contract_deployed(&state_reader, state_number, contract_address)?;
let res = state_reader.get_nonce_at(...)?
    .ok_or(StateSyncError::ContractNotFound(contract_address))?;
``` [6](#0-5) 

This is the correct behavior from state sync's perspective — the account genuinely does not exist at block N-1. The problem is that both readers treat this as "account never existed" rather than "account exists but not yet visible."

**The race window:**

`instantiate_validator` is called fresh per transaction: [7](#0-6) 

Between block N being committed (containing the original `DeployAccount`) and state sync updating its `latest_block_number` to N, any incoming transaction validation will snapshot at N-1. The account deployed in block N is invisible to all validation layers.

---

### Impact Explanation

The full validation pipeline — `validate_nonce`, `validate_by_mempool`, and `run_validate_entry_point` (blockifier) — all operate on the same stale N-1 state. The blockifier sees `class_hash == 0` (undeployed) and `nonce == 0`, so it:
1. Succeeds in "deploying" the contract in its local `CachedState`
2. Runs `__validate_deploy__` (which the account owner can sign correctly)
3. Returns `Ok(())`

The duplicate `DeployAccount` is then forwarded to the mempool. The concrete corrupted admission value is: **a `DeployAccount` transaction for an already-deployed account is accepted into the mempool**, violating the invariant that `account_nonce > 0` implies the account is deployed and no further `DeployAccount` should be admitted. [8](#0-7) 

---

### Likelihood Explanation

The race window is real and bounded only by the latency between block finalization and state sync propagation. An account owner who deploys their account and immediately resubmits the same `DeployAccount` transaction (with valid signature) can reliably hit this window, especially under load or with a slow state sync. No privileged access is required — only knowledge of one's own deployment parameters (class hash, salt, constructor calldata), which the account owner trivially possesses.

---

### Recommendation

1. **Distinguish `ContractNotFound` from "nonce is zero"** in `GatewayFixedBlockSyncStateClient::get_nonce`. For `DeployAccount` validation, a `ContractNotFound` response should be treated as "account not yet visible at this block" and either propagated as an error or explicitly gated: only return `Nonce::default()` if the queried block is the genesis/bootstrap case.

2. **Add a deployed-account guard in `validate_nonce`**: before accepting a `DeployAccount` tx, also check `get_class_hash_at` — if it returns a non-zero class hash, reject. This is a defense-in-depth check that does not depend on nonce alone.

3. **Consider using `get_class_hash_at` as the authoritative "is deployed" signal** rather than inferring deployment from nonce, since `class_hash == 0` is the canonical "undeployed" sentinel in Starknet state.

---

### Proof of Concept

```rust
// Minimal Rust unit test sketch (production path only, no mocks needed for the logic):
//
// 1. Create a MockStateSyncClient that returns ContractNotFound for get_nonce_at
//    at block N-1 for address A (simulating the race window).
// 2. Create GatewayFixedBlockSyncStateClient with block N-1.
// 3. Call get_nonce(A) → assert returns Nonce(0).
// 4. Build a StatefulTransactionValidator with the same stale block for both readers.
// 5. Call validate_nonce with a DeployAccount tx (nonce=0) for address A.
// 6. Assert Ok(()) is returned — the gateway-level check is bypassed.
// 7. Confirm SyncStateReader::get_nonce_at and get_class_hash_at also return
//    Nonce(0) / ClassHash(0) for the same ContractNotFound response,
//    meaning run_validate_entry_point also proceeds without rejection.
```

The existing test `test_deploy_account_nonce_validation` with `account_nonce=0` already confirms step 6 passes: [9](#0-8) 

The missing test is the one that feeds `ContractNotFound` from a mock `StateSyncClient` for an address that has a non-zero nonce in a later block — that test would demonstrate the race produces `Nonce(0)` and admission succeeds.

### Citations

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L72-74)
```rust
            Err(StateSyncClientError::StateSyncError(StateSyncError::ContractNotFound(_))) => {
                Ok(Nonce::default())
            }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L86-119)
```rust
    async fn instantiate_validator(
        &self,
        native_classes_whitelist: NativeClassesWhitelist,
    ) -> StatefulTransactionValidatorResult<Box<Self::Validator>> {
        // TODO(yael 6/5/2024): consider storing the block_info as part of the
        // StatefulTransactionValidator and update it only once a new block is created.
        let (blockifier_state_reader, gateway_fixed_block_state_reader) = self
            .state_reader_factory
            .get_blockifier_state_reader_and_gateway_fixed_block_from_latest_block()
            .await
            .map_err(|err| GatewaySpecError::UnexpectedError {
                data: format!("Internal server error: {err}"),
            })
            .map_err(|e| {
                StarknetError::internal_with_logging(
                    "Failed to get state reader from latest block",
                    e,
                )
            })?;
        let state_reader_and_contract_manager =
            StateReaderAndContractManager::new_with_native_classes_whitelist(
                blockifier_state_reader,
                self.contract_class_manager.clone(),
                native_classes_whitelist,
                Some(GATEWAY_CLASS_CACHE_METRICS),
            );

        Ok(Box::new(StatefulTransactionValidator::new(
            self.config.clone(),
            self.chain_info.clone(),
            state_reader_and_contract_manager,
            gateway_fixed_block_state_reader,
        )))
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L273-284)
```rust
            ExecutableTransaction::DeployAccount(_) => {
                if account_nonce != Nonce(Felt::ZERO) {
                    return Err(create_error(format!(
                        "Invalid deploy account transaction. Account is already deployed \
                         (nonce={account_nonce})."
                    )));
                }
                if incoming_tx_nonce != Nonce(Felt::ZERO) {
                    return Err(create_error(format!(
                        "Invalid transaction nonce. Expected: nonce = 0, got: {incoming_tx_nonce}."
                    )));
                }
```

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

**File:** crates/apollo_gateway/src/sync_state_reader.rs (L156-168)
```rust
    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let res = self
            .runtime
            .block_on(self.state_sync_client.get_nonce_at(self.block_number, contract_address));

        match res {
            Ok(value) => Ok(value),
            Err(StateSyncClientError::StateSyncError(StateSyncError::ContractNotFound(_))) => {
                Ok(Nonce::default())
            }
            Err(e) => Err(StateError::StateReadError(e.to_string())),
        }
    }
```

**File:** crates/apollo_gateway/src/sync_state_reader.rs (L183-195)
```rust
    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let res = self.runtime.block_on(
            self.state_sync_client.get_class_hash_at(self.block_number, contract_address),
        );

        match res {
            Ok(value) => Ok(value),
            Err(StateSyncClientError::StateSyncError(StateSyncError::ContractNotFound(_))) => {
                Ok(ClassHash::default())
            }
            Err(e) => Err(StateError::StateReadError(e.to_string())),
        }
    }
```

**File:** crates/apollo_gateway/src/sync_state_reader.rs (L531-549)
```rust
        let latest_block_number = self.shared_state_sync_client.get_latest_block_number().await?;

        // If no blocks exist yet, return genesis state readers for bootstrap transactions.
        let Some(latest_block_number) = latest_block_number else {
            info!("No blocks found yet; using genesis state readers for bootstrap transactions.");
            return Ok((GenesisStateReader.into(), GenesisFixedBlockStateReader.into()));
        };

        let blockifier_state_reader = SyncStateReader::from_number(
            self.shared_state_sync_client.clone(),
            self.class_manager_client.clone(),
            latest_block_number,
            self.runtime.clone(),
        );
        let gateway_fixed_block_sync_state_client = GatewayFixedBlockSyncStateClient::new(
            self.shared_state_sync_client.clone(),
            latest_block_number,
        );
        Ok((blockifier_state_reader.into(), gateway_fixed_block_sync_state_client.into()))
```

**File:** crates/apollo_state_sync/src/lib.rs (L271-275)
```rust
        verify_contract_deployed(&state_reader, state_number, contract_address)?;

        let res = state_reader
            .get_nonce_at(state_number, &contract_address)?
            .ok_or(StateSyncError::ContractNotFound(contract_address))?;
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L388-412)
```rust
#[rstest]
#[case::all_nonces_zero(0, 0, Ok(false))]
#[case::tx_nonce_nonzero(
    0,
    1,
    Err(StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::InvalidTransactionNonce))
)]
#[case::account_nonce_nonzero(
    1,
    0,
    Err(StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::InvalidTransactionNonce))
)]
#[tokio::test]
async fn test_deploy_account_nonce_validation(
    #[case] account_nonce: u32,
    #[case] tx_nonce: u32,
    #[case] expected_result: Result<bool, StarknetErrorCode>,
) {
    let executable_tx = executable_deploy_account_tx(deploy_account_tx_args!(
        nonce: nonce!(tx_nonce),
        resource_bounds: ValidResourceBounds::create_for_testing(),
    ));

    run_pre_validation_checks_test(executable_tx, nonce!(account_nonce), 0, expected_result).await;
}
```
