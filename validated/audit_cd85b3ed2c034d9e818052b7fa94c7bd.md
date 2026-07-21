### Title
Gateway `run_validate_entry_point` increments block number via `unchecked_next()` but reads block-hash contract from the prior block's state, causing valid client-side proving transactions to be incorrectly rejected — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful validation path increments the block number by one (`block_info.block_number.unchecked_next()`) to simulate the upcoming block, but the underlying state reader still reflects the **previous** committed block. The `validate_proof_block_number` check therefore permits proof facts referencing block `N − (STORED_BLOCK_HASH_BUFFER − 1)` (i.e., `N − 9`), while `validate_proof_block_hash` reads the block-hash contract from state at block `N`, which only contains hashes up to block `N − STORED_BLOCK_HASH_BUFFER` (i.e., `N − 10`). The hash for block `N − 9` is written to state only when `pre_process_block` runs at the start of block `N + 1` execution — after gateway admission. Any Invoke V3 transaction carrying SNOS proof facts that references block `N − 9` is therefore permanently rejected at the gateway with "Block hash mismatch", even though the same transaction would succeed during actual block execution.

---

### Finding Description

**Step 1 — Block number is incremented without updating the block-hash contract.**

In `run_validate_entry_point`, the gateway builds a synthetic block context for the *next* block:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();   // N → N+1
``` [1](#0-0) 

The state reader, however, is still rooted at block `N`:

```rust
let state = CachedState::new(state_reader_and_contract_manager);
let mut blockifier_validator = StatefulValidator::create(state, block_context);
``` [2](#0-1) 

**Step 2 — `validate_proof_block_number` allows block `N − 9`.**

With `current_block_number = N + 1`, the maximum allowed proof block number is:

```rust
let max_allowed = current_block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER)…;
// max_allowed = (N+1) − 10 = N − 9
if proof_block_number > max_allowed { return Err(…) }
``` [3](#0-2) 

**Step 3 — `validate_proof_block_hash` reads from state at block `N`, which only has hashes up to `N − 10`.**

```rust
let stored_block_hash = state
    .get_storage_at(block_hash_contract_address, StorageKey::from(proof_block_number))?;
// proof_block_number = N−9 → stored_block_hash = Felt::ZERO (not yet written)

if stored_block_hash != proof_block_hash {
    return Err(TransactionPreValidationError::InvalidProofFacts(
        "Block hash mismatch …"
    ));
}
``` [4](#0-3) 

**Step 4 — `pre_process_block` writes the hash of block `N − 9` only when block `N + 1` is actually executed.**

```rust
// Called at the start of block N+1 execution, before any transaction runs:
state.set_storage_at(block_hash_contract_address, block_number_as_storage_key, hash.0)?;
// Writes hash of block (N+1) − STORED_BLOCK_HASH_BUFFER = N − 9
``` [5](#0-4) 

**Step 5 — `validate_proof_facts` is called inside `perform_pre_validation_stage`, which is called by `perform_validations` for every Invoke transaction.**

```rust
ApiTransaction::Invoke(_) => {
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    …
}
``` [6](#0-5) 

```rust
self.validate_proof_facts(&tx_context.block_context, state)?;
``` [7](#0-6) 

**Consequence:** A valid Invoke V3 transaction with SNOS proof facts referencing block `N − 9` is rejected at the gateway with `InvalidProofFacts("Block hash mismatch")`. The same transaction, if somehow admitted, would succeed during actual execution of block `N + 1` because `pre_process_block` writes the hash of block `N − 9` before any transaction runs.

---

### Impact Explanation

This matches the **High** impact category: *"Mempool/gateway/RPC admission … rejects valid transactions before sequencing."*

Every client-side proving transaction (Invoke V3 with non-empty `proof_facts`) that references the most recent permissible block (`N − 9`) is permanently rejected at the gateway. The user cannot work around this by retrying — the transaction is structurally valid and would succeed in the batcher, but the gateway's off-by-one in the block-hash availability window makes it impossible to use the freshest allowed block reference. This degrades the client-side proving UX and breaks the invariant that the gateway admission decision matches the blockifier execution decision.

---

### Likelihood Explanation

Any user generating a SNOS proof against the most recent eligible block (a natural choice for minimizing proof staleness) will hit this rejection. The trigger requires no special privileges: submit an Invoke V3 transaction with `proof_facts` whose `block_number` field equals `N − 9`. The gateway will always reject it with "Block hash mismatch" regardless of how correct the proof is.

---

### Recommendation

Before calling `validate_proof_facts`, the gateway should either:

1. **Restrict the allowed proof block number** to `N − STORED_BLOCK_HASH_BUFFER` (i.e., `N − 10`) instead of `(N+1) − STORED_BLOCK_HASH_BUFFER`, so the number check matches what is actually available in the state. Concretely, do not apply `unchecked_next()` to the block number used inside `validate_proof_block_number`, or apply it only for fee-related checks.

2. **Alternatively**, simulate `pre_process_block` on the cached state before running `validate_proof_facts`, so the block-hash contract reflects the state that will exist when the transaction is actually executed.

---

### Proof of Concept

Let `N = 100`, `STORED_BLOCK_HASH_BUFFER = 10`.

1. Latest committed block is `100`. State contains block-hash entries for blocks `0–90`.
2. User constructs an Invoke V3 transaction with `proof_facts.block_number = 91` (= `N − 9`), which is the maximum allowed by `validate_proof_block_number` with `current_block_number = 101`.
3. Gateway calls `run_validate_entry_point`:
   - `block_info.block_number = 101` (via `unchecked_next()`)
   - `validate_proof_block_number(91, 101)` → `max_allowed = 91` → **passes**
   - `validate_proof_block_hash(proof_hash, 91, state_at_block_100)` → `stored = Felt::ZERO` → **"Block hash mismatch" → rejected**
4. If the same transaction were admitted and executed in block `101`:
   - `pre_process_block` writes `hash(block 91)` to state
   - `validate_proof_block_hash(proof_hash, 91, state_at_block_101)` → `stored = hash(block 91)` → **passes**
   - Transaction executes successfully. [8](#0-7) [9](#0-8) [5](#0-4)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L291-351)
```rust
    fn validate_proof_facts(
        &self,
        block_context: &BlockContext,
        state: &mut dyn State,
    ) -> TransactionPreValidationResult<()> {
        // Only Invoke V3 transactions can carry proof facts.
        let Transaction::Invoke(invoke_tx) = &self.tx else {
            return Ok(());
        };
        if invoke_tx.version() < TransactionVersion::THREE {
            return Ok(());
        }

        // Parse proof facts.
        let proof_facts = invoke_tx.proof_facts();
        let snos_proof_facts = match ProofFactsVariant::try_from(&proof_facts)
            .map_err(|e| TransactionPreValidationError::InvalidProofFacts(e.to_string()))?
        {
            ProofFactsVariant::Empty => return Ok(()),
            ProofFactsVariant::Snos(snos_proof_facts) => snos_proof_facts,
        };
        let os_constants = &block_context.versioned_constants.os_constants;

        if !os_constants.allowed_proof_versions.contains(&snos_proof_facts.proof_version.as_felt())
        {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "Proof version {} is not allowed under this protocol version.",
                snos_proof_facts.proof_version
            )));
        }

        // Validate the program hash.
        let allowed = &os_constants.allowed_virtual_os_program_hashes;
        if !allowed.contains(&snos_proof_facts.program_hash) {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "Virtual OS program hash {} is not allowed",
                snos_proof_facts.program_hash
            )));
        }

        // Validate the block hash and block number.
        let proof_block_hash = snos_proof_facts.block_hash.0;
        let proof_block_number = snos_proof_facts.block_number.0;
        Self::validate_proof_block_number(
            proof_block_number,
            block_context.block_info.block_number,
        )?;
        Self::validate_proof_block_hash(proof_block_hash, proof_block_number, os_constants, state)?;

        // Validate the config hash.
        let virtual_os_config_hash = block_context.virtual_os_config_hash();
        let proof_config_hash = snos_proof_facts.config_hash;
        if virtual_os_config_hash != proof_config_hash {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "Virtual OS config hash mismatch. Computed virtual OS config hash: \
                 {virtual_os_config_hash}, expected virtual OS config hash: {proof_config_hash}."
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-78)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
```
