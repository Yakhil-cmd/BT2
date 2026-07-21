### Title
Gateway Proof-Facts Block-Hash Check Rejects Valid Transactions Due to State/Block-Number Mismatch — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`run_validate_entry_point` advances the block number by one (`unchecked_next()`) to simulate the next block, but reads block-hash storage from the **previous** block's state. This creates a one-block window where `validate_proof_block_number` permits a proof referencing block `N − STORED_BLOCK_HASH_BUFFER + 1`, yet `validate_proof_block_hash` always returns "Block hash mismatch" for that same block number because its hash has not yet been written to storage. The transaction would succeed at execution time (after `pre_process_block` writes the hash), but is permanently rejected at the gateway.

### Finding Description

**Gateway block-number bump**

`run_validate_entry_point` fetches the latest committed block info and increments the block number before constructing the `BlockContext` passed to the blockifier validator:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();   // N → N+1
``` [1](#0-0) 

**Proof-block-number bound derived from the bumped number**

`validate_proof_block_number` computes the maximum allowed proof block number as `current_block_number − STORED_BLOCK_HASH_BUFFER`:

```rust
let max_allowed =
    current_block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER).ok_or_else(|| { ... })?;
if proof_block_number > max_allowed { return Err(...); }
``` [2](#0-1) 

With the bumped block number `N+1`, `max_allowed = N − STORED_BLOCK_HASH_BUFFER + 1`. A proof referencing that block number passes this check.

**Block-hash lookup reads stale state**

`validate_proof_block_hash` immediately reads the block-hash contract storage using the **same state** that was snapshotted from block N:

```rust
let stored_block_hash = state
    .get_storage_at(block_hash_contract_address, StorageKey::from(proof_block_number))?;
if stored_block_hash != proof_block_hash {
    return Err(TransactionPreValidationError::InvalidProofFacts(...));
}
``` [3](#0-2) 

`pre_process_block` writes the hash for block `N − STORED_BLOCK_HASH_BUFFER + 1` only **during** the processing of block `N+1`:

```rust
// Writes the hash of the (current_block_number - N) block under its block number
// in the dedicated contract state, where N=STORED_BLOCK_HASH_BUFFER.
pub fn pre_process_block(state, old_block_number_and_hash, next_block_number, ...) { ... }
``` [4](#0-3) 

At gateway-validation time the state is from block N, so `get_storage_at(block_hash_contract_address, N − STORED_BLOCK_HASH_BUFFER + 1)` returns `Felt::ZERO`. Any non-zero hash supplied by the user triggers "Block hash mismatch" and the transaction is rejected.

**Execution-time behaviour is correct**

When the batcher processes block `N+1`, `pre_process_block` writes the hash for `N − STORED_BLOCK_HASH_BUFFER + 1` before any transaction is executed. The same `validate_proof_facts` call would then succeed. The gateway is therefore stricter than the execution layer by exactly one block.

`STORED_BLOCK_HASH_BUFFER = 10` is defined in the OS constants: [5](#0-4) 

### Impact Explanation

Any Invoke V3 transaction carrying SNOS proof facts that reference the most recently available block (`N − STORED_BLOCK_HASH_BUFFER + 1`) is permanently rejected by the gateway with a spurious "Block hash mismatch" error. The transaction cannot be resubmitted with a different proof block number without invalidating the proof itself. This matches the **High** impact criterion: *"Mempool/gateway/RPC admission rejects valid transactions before sequencing."*

### Likelihood Explanation

The window is exactly one block wide and is always present. Any client-side proving workflow that generates a proof against the most recent eligible block (a natural choice to minimise proof staleness) will hit this rejection on every submission attempt. The condition is deterministic and reproducible.

### Recommendation

Align the block-hash availability check with the state actually used for validation. Two options:

1. **Reduce the effective max-allowed proof block number by one** inside `run_validate_entry_point` so that the gateway only permits proof block numbers whose hashes are already present in the snapshotted state (`max_allowed = N − STORED_BLOCK_HASH_BUFFER`, not `N − STORED_BLOCK_HASH_BUFFER + 1`).

2. **Apply the block-number bump only to fields that do not depend on storage** (e.g. nonce checks), and keep the proof-facts block-hash lookup using the un-bumped block number so the storage read is consistent with the available state.

### Proof of Concept

Let `N = 20`, `STORED_BLOCK_HASH_BUFFER = 10`.

1. Latest committed block is 20. State contains block hashes for blocks 0–10.
2. User constructs a proof referencing block 11 (= 20 − 10 + 1). The hash of block 11 is publicly known but not yet in the block-hash contract storage.
3. User submits an Invoke V3 transaction with `proof_facts.block_number = 11`, `proof_facts.block_hash = <real hash of block 11>`.
4. Gateway calls `run_validate_entry_point`, bumps block number to 21.
5. `validate_proof_block_number(11, 21)` → `max_allowed = 21 − 10 = 11` → **passes**.
6. `validate_proof_block_hash(real_hash, 11, state_at_block_20)` → `get_storage_at(block_hash_contract, 11)` returns `Felt::ZERO` → `Felt::ZERO ≠ real_hash` → **"Block hash mismatch" error**.
7. Transaction is rejected. The user cannot submit this proof through the gateway.
8. If the batcher were to execute this transaction in block 21, `pre_process_block` would first write `hash(block 11)` to storage, and the same check would **pass**. [6](#0-5) [7](#0-6)

### Citations

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L238-289)
```rust
    fn validate_proof_block_number(
        proof_block_number: u64,
        current_block_number: BlockNumber,
    ) -> TransactionPreValidationResult<()> {
        // Proof block must be old enough to have a stored block hash.
        // Stored block hashes are guaranteed only up to: current - STORED_BLOCK_HASH_BUFFER.
        let max_allowed =
            current_block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER).ok_or_else(|| {
                TransactionPreValidationError::InvalidProofFacts(format!(
                    "The current block number {current_block_number} is below the required \
                     block-hash retention buffer: {STORED_BLOCK_HASH_BUFFER}."
                ))
            })?;

        if proof_block_number > max_allowed {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "The proof block number {proof_block_number} is too recent. The maximum allowed \
                 block number is {max_allowed}."
            )));
        }

        Ok(())
    }

    fn validate_proof_block_hash(
        proof_block_hash: Felt,
        proof_block_number: u64,
        os_constants: &OsConstants,
        state: &mut dyn State,
    ) -> TransactionPreValidationResult<()> {
        if proof_block_hash == Felt::ZERO {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "Proof block hash is zero for block {proof_block_number}."
            )));
        }

        // Compare the proof's block hash with the stored block hash.
        let block_hash_contract_address =
            os_constants.os_contract_addresses.block_hash_contract_address();

        let stored_block_hash = state
            .get_storage_at(block_hash_contract_address, StorageKey::from(proof_block_number))?;

        if stored_block_hash != proof_block_hash {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "Block hash mismatch for block {proof_block_number}. Proof block hash: \
                 {proof_block_hash}, stored block hash: {stored_block_hash}."
            )));
        }

        Ok(())
    }
```

**File:** crates/blockifier/src/blockifier/block.rs (L18-35)
```rust
pub fn pre_process_block(
    state: &mut dyn State,
    old_block_number_and_hash: Option<BlockHashAndNumber>,
    next_block_number: BlockNumber,
    os_constants: &OsConstants,
) -> StateResult<()> {
    let should_block_hash_be_provided =
        next_block_number >= BlockNumber(constants::STORED_BLOCK_HASH_BUFFER);
    if let Some(BlockHashAndNumber { number, hash }) = old_block_number_and_hash {
        let block_hash_contract_address =
            os_constants.os_contract_addresses.block_hash_contract_address();
        let block_number_as_storage_key = StorageKey::from(number.0);
        state.set_storage_at(block_hash_contract_address, block_number_as_storage_key, hash.0)?;
    } else if should_block_hash_be_provided {
        return Err(StateError::OldBlockHashNotProvided);
    }

    Ok(())
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/constants.cairo (L65-65)
```text
const STORED_BLOCK_HASH_BUFFER = 10;
```
