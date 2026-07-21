Let me look at the `StatefulValidator::validate` call chain and `perform_pre_validation_stage` to confirm the full path.

The full call chain is confirmed. Here is the complete analysis:

---

### Title
Gateway Rejects Valid Invoke-with-Proof When `proof_block_number = latest - STORED_BLOCK_HASH_BUFFER + 1` Due to State/Block-Number Skew — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`run_validate_entry_point` advances `block_info.block_number` by one (`unchecked_next()`) before building the `BlockContext` passed to blockifier, but the underlying `CachedState` remains at the tip (`latest`). `validate_proof_facts` uses the advanced block number to compute the maximum allowed proof block number, opening a one-block window (`latest - STORED_BLOCK_HASH_BUFFER + 1`) that passes the numeric range check but whose block hash is not yet written into the tip state. The hash lookup returns `Felt::ZERO`, triggering `InvalidProofFacts` and rejecting a transaction that would be accepted without error during actual block execution of block `latest + 1`.

### Finding Description

**Call chain:**

1. `extract_state_nonce_and_run_validations` → `run_validate_entry_point` [1](#0-0) 

2. Inside `run_validate_entry_point`, the block number is advanced but the state is not: [2](#0-1) 

3. `StatefulValidator::perform_validations` calls `perform_pre_validation_stage` with this advanced `block_context` and the tip-state: [3](#0-2) 

4. `perform_pre_validation_stage` calls `validate_proof_facts`: [4](#0-3) 

5. `validate_proof_block_number` computes `max_allowed = (latest+1) - STORED_BLOCK_HASH_BUFFER = latest - STORED_BLOCK_HASH_BUFFER + 1`, so a proof referencing that block number passes: [5](#0-4) 

6. `validate_proof_block_hash` then reads the stored hash for `latest - STORED_BLOCK_HASH_BUFFER + 1` from the tip state. That hash is not yet written (it is written by the OS at the *start* of block `latest+1`, before any transactions run), so `get_storage_at` returns `Felt::ZERO`. Since the proof carries the real non-zero hash, the comparison fails and `InvalidProofFacts` is returned: [6](#0-5) 

**Why the transaction is valid in execution:** The Cairo OS stores the hash for block `N - STORED_BLOCK_HASH_BUFFER` at the very start of block `N`, before any user transactions are processed. So when block `latest+1` is actually built, the hash for `latest - STORED_BLOCK_HASH_BUFFER + 1` is present in state and `check_proof_facts` in the OS succeeds: [7](#0-6) 

`STORED_BLOCK_HASH_BUFFER = 10` is the constant governing both sides: [8](#0-7) 

### Impact Explanation

Any Invoke V3 transaction carrying SNOS proof facts with `proof_block_number = latest - STORED_BLOCK_HASH_BUFFER + 1` (i.e., the single newest block that the advanced block-number check admits) is permanently rejected at the gateway with `ValidateFailure / InvalidProofFacts`. The transaction is structurally valid and would execute successfully if included in block `latest+1`. This is a systematic, deterministic valid-transaction rejection at the admission layer.

Impact category: **High — Mempool/gateway admission rejects valid transactions before sequencing.**

### Likelihood Explanation

A client-side prover generating proof facts for the most recent eligible block will naturally target `latest - STORED_BLOCK_HASH_BUFFER + 1` (the freshest block whose hash is available on-chain). This is the expected boundary case for any latency-minimizing prover. The rejection is silent from the user's perspective (they receive a `ValidateFailure` with no indication that the block number is the cause), making it hard to diagnose.

### Recommendation

Align the block number used for the proof-facts range check with the block whose hashes are actually present in the gateway state. Two options:

- **Option A (conservative):** In `validate_proof_block_number`, pass `block_context.block_info.block_number - 1` (i.e., the tip block number before `unchecked_next()`) so that `max_allowed = latest - STORED_BLOCK_HASH_BUFFER`, matching what is actually stored. This makes the gateway slightly more conservative than execution (by one block), but eliminates the false rejection.
- **Option B (precise):** Before running `validate_proof_block_hash`, inject the hash for `latest - STORED_BLOCK_HASH_BUFFER + 1` into the cached state (it is computable from the chain tip), so the lookup succeeds for the boundary block.

### Proof of Concept

```rust
// Pseudocode for a unit test over perform_pre_validation_stage:
let latest = BlockNumber(100);
// State contains hashes only up to block 100 - 10 = 90.
// block_context.block_info.block_number = 101 (after unchecked_next).
// proof_block_number = 101 - 10 = 91 → passes validate_proof_block_number.
// But state has no hash for block 91 → stored_block_hash = Felt::ZERO.
// proof_block_hash = real_hash_of_block_91 ≠ Felt::ZERO → InvalidProofFacts.
// Expected: Ok(()), Actual: Err(InvalidProofFacts("Block hash mismatch for block 91..."))
```

The existing test suite already demonstrates the boundary semantics: [9](#0-8) 

That test uses `CURRENT_BLOCK_NUMBER` directly (not `CURRENT_BLOCK_NUMBER + 1`) as the context block number, so it does not reproduce the gateway's `unchecked_next()` skew. A test that sets `block_context.block_info.block_number = N+1` while the state only stores hashes up to `N - STORED_BLOCK_HASH_BUFFER` and submits `proof_block_number = N - STORED_BLOCK_HASH_BUFFER + 1` will reproduce the rejection.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-340)
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
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-79)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
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

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/execution_constraints.cairo (L65-78)
```text
    // Validate that the proof facts block number is not too recent.
    // (This is a sanity check - the following non-zero check ensures that the block hash is
    // not trivial).
    assert_nn_le(
        os_output_header.base_block_number, current_block_number - STORED_BLOCK_HASH_BUFFER
    );
    // Not all block hashes are stored in the contract; Make sure the requested one is not trivial.
    assert_not_zero(os_output_header.base_block_hash);

    // validate that the proof facts block hash is the true hash of the proof facts block number.
    read_block_hash_from_storage(
        block_number=os_output_header.base_block_number,
        expected_block_hash=os_output_header.base_block_hash,
    );
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/constants.cairo (L64-65)
```text
// The block number -> block hash mapping is written for the current block number minus this number.
const STORED_BLOCK_HASH_BUFFER = 10;
```

**File:** crates/blockifier/src/transaction/account_transactions_test.rs (L2249-2261)
```rust
/// Returns invalid proof_facts with a too recent block number (at the boundary).
fn proof_facts_with_too_recent_block() -> ProofFacts {
    // Set the proof block number to the first invalid value:
    // `current_block_number - STORED_BLOCK_HASH_BUFFER + 1`
    // (i.e. last allowed block + 1).
    create_valid_proof_facts_for_testing()
        .try_into()
        .map(|mut snos: SnosProofFacts| {
            snos.block_number = BlockNumber(CURRENT_BLOCK_NUMBER - STORED_BLOCK_HASH_BUFFER + 1);
            snos_to_proof_facts(snos)
        })
        .unwrap()
}
```
