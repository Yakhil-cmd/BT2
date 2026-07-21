### Title
Gateway `validate_proof_block_number` uses incremented block N+1 but state snapshot lacks the corresponding `pre_process_block` write, causing valid proof-carrying transactions to be rejected - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `run_validate_entry_point` simulates execution at block `N+1` by incrementing the latest committed block number (`block_info.block_number.unchecked_next()`), but it supplies the state reader from block `N` **without** calling `pre_process_block`. The `validate_proof_block_number` check therefore permits `proof_block_number` up to `N+1 − STORED_BLOCK_HASH_BUFFER`, while `validate_proof_block_hash` reads from the block-N state where the hash for that exact block number has not yet been written. The result is that a valid invoke-V3 transaction referencing the most-recently-allowed proof block is rejected at the gateway but would be accepted by the batcher.

### Finding Description

**Step 1 – Gateway increments block number but not state.**

In `run_validate_entry_point`:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();   // N → N+1
let block_context = BlockContext::new(block_info, ...);
// state reader is still from block N — no pre_process_block called
let state = CachedState::new(state_reader_and_contract_manager);
let mut blockifier_validator = StatefulValidator::create(state, block_context);
blockifier_validator.validate(account_tx)
``` [1](#0-0) 

**Step 2 – `validate_proof_facts` is always called inside `perform_pre_validation_stage`.**

For every invoke transaction, `StatefulValidator::perform_validations` calls `perform_pre_validation_stage`, which unconditionally calls `validate_proof_facts` regardless of `skip_validate` or `charge_fee`. [2](#0-1) 

**Step 3 – `validate_proof_block_number` uses the incremented block number N+1.**

```rust
fn validate_proof_block_number(proof_block_number: u64, current_block_number: BlockNumber) -> ... {
    let max_allowed = current_block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER)...;
    if proof_block_number > max_allowed { return Err(...); }
    Ok(())
}
```

With `current_block_number = N+1`, `max_allowed = N+1 − STORED_BLOCK_HASH_BUFFER`. A transaction with `proof_block_number = N+1 − STORED_BLOCK_HASH_BUFFER` passes this check. [3](#0-2) 

**Step 4 – `validate_proof_block_hash` reads from state at block N, where that hash is absent.**

`pre_process_block` writes the hash of block `next_block_number − STORED_BLOCK_HASH_BUFFER` into the block-hash contract. At block N the stored hashes only go up to `N − STORED_BLOCK_HASH_BUFFER`. The hash for `N+1 − STORED_BLOCK_HASH_BUFFER` is written only when block N+1 is processed. [4](#0-3) 

Because the gateway never calls `pre_process_block`, `state.get_storage_at(block_hash_contract, N+1−STORED_BLOCK_HASH_BUFFER)` returns `Felt::ZERO`. The check `stored_block_hash != proof_block_hash` then fails (the zero-hash guard also fires), and the gateway returns a `ValidateFailure` error. [5](#0-4) 

**Step 5 – The batcher accepts the same transaction.**

`ConcurrentTransactionExecutor::start_block` (used by the batcher's `BlockBuilderFactory`) calls `pre_process_block` before any transaction is executed, writing the hash for `N+1 − STORED_BLOCK_HASH_BUFFER` into the state. The identical transaction then passes `validate_proof_block_hash`. [6](#0-5) 

### Impact Explanation

A user who constructs a valid SNOS-proof-carrying invoke-V3 transaction referencing `proof_block_number = N+1 − STORED_BLOCK_HASH_BUFFER` (the most recent block the protocol would allow in the next block) will receive a `ValidateFailure` rejection from the gateway. The transaction is protocol-valid and would execute successfully in the batcher. This matches the "High" impact criterion: **gateway admission rejects a valid transaction before sequencing**.

### Likelihood Explanation

The failure is deterministic and reproducible. Any client that computes the maximum allowed proof block number as `latest_block − STORED_BLOCK_HASH_BUFFER + 1` (which is the correct upper bound for the block being built) will always be rejected. The off-by-one is structural, not timing-dependent.

### Recommendation

In `run_validate_entry_point`, either:

1. **Do not increment the block number** for the purpose of proof-facts validation — use `block_info.block_number` (block N) as `current_block_number`, consistent with the state snapshot that is actually available; or
2. **Call `pre_process_block`** on the cached state before creating the `StatefulValidator`, mirroring what `ConcurrentTransactionExecutor::start_block` does, so the state and the block number are consistent.

Option 1 is simpler and sufficient: the gateway should validate proof facts against the state it actually holds (block N), not against a hypothetical future state (block N+1).

### Proof of Concept

Let `N` = latest committed block, `B` = `STORED_BLOCK_HASH_BUFFER`.

1. User constructs an invoke-V3 tx with `proof_block_number = N+1−B` and the correct stored hash for that block (which is publicly known from chain history).
2. User submits to the gateway.
3. Gateway builds `BlockContext` with `block_number = N+1`, state from block N.
4. `validate_proof_block_number`: `N+1−B <= N+1−B` → **passes**.
5. `validate_proof_block_hash`: reads storage slot `N+1−B` from block-N state → returns `Felt::ZERO` → **fails** with "Block hash mismatch … stored block hash: 0".
6. Gateway returns `ValidateFailure`; transaction is never admitted to the mempool.
7. If the same transaction were submitted one block later (when the gateway's latest block is N+1), `pre_process_block` has now written the hash for `N+1−B`, and the transaction would pass.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-341)
```rust
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
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L238-260)
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
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L262-289)
```rust
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

**File:** crates/blockifier/src/blockifier/concurrent_transaction_executor.rs (L43-49)
```rust
        let mut block_state = CachedState::new(initial_state_reader);
        pre_process_block(
            &mut block_state,
            old_block_number_and_hash,
            block_context.block_info().block_number,
            &block_context.versioned_constants.os_constants,
        )?;
```
