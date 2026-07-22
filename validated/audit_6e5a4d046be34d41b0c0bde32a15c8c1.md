### Title
Gateway `validate_proof_facts` falsely rejects valid proof-bearing invoke transactions due to block-number/state inconsistency in `run_validate_entry_point` - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `run_validate_entry_point` increments the block number by 1 (`unchecked_next()`) to simulate the next block, but uses the state reader from the current (latest) block N. The `validate_proof_facts` function uses the incremented block number N+1 to compute `max_allowed = (N+1) − STORED_BLOCK_HASH_BUFFER`, permitting proof facts that reference block `N − STORED_BLOCK_HASH_BUFFER + 1`. However, the block hash for that block is not yet stored in the state (it is only written by `pre_process_block` when block N+1 is actually processed). As a result, `validate_proof_block_hash` reads `Felt::ZERO` from storage and fails with "Block hash mismatch", falsely rejecting a transaction that would pass all checks during real execution in block N+1.

---

### Finding Description

**Step 1 – Gateway inflates block number but not state.**

In `run_validate_entry_point`, the gateway fetches the latest committed block info and bumps the block number by one before constructing the `BlockContext` passed to the blockifier validator:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();   // N → N+1
let block_context = BlockContext::new(block_info, ...);
``` [1](#0-0) 

The state reader, however, is still anchored to block N — no `pre_process_block` is called to populate the block-hash contract for block N+1.

**Step 2 – `validate_proof_block_number` uses the inflated block number.**

`perform_pre_validation_stage` → `validate_proof_facts` → `validate_proof_block_number` computes:

```rust
let max_allowed =
    current_block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER)...;
// current_block_number = N+1  →  max_allowed = N − STORED_BLOCK_HASH_BUFFER + 1
if proof_block_number > max_allowed { return Err(...) }
``` [2](#0-1) 

A transaction with `proof_block_number = N − STORED_BLOCK_HASH_BUFFER + 1` passes this check.

**Step 3 – `validate_proof_block_hash` reads from the stale state.**

```rust
let stored_block_hash = state
    .get_storage_at(block_hash_contract_address, StorageKey::from(proof_block_number))?;
// proof_block_number = N − STORED_BLOCK_HASH_BUFFER + 1
// stored_block_hash  = Felt::ZERO  (not yet written; written only during block N+1 processing)
if stored_block_hash != proof_block_hash {
    return Err(...)   // "Block hash mismatch"
}
``` [3](#0-2) 

The block hash for block `N − STORED_BLOCK_HASH_BUFFER + 1` is written by `pre_process_block` only when block N+1 is being built:

```rust
// Writes hash of block (next_block_number − STORED_BLOCK_HASH_BUFFER) into storage.
state.set_storage_at(block_hash_contract_address, block_number_as_storage_key, hash.0)?;
``` [4](#0-3) 

Because the gateway state is from block N (before `pre_process_block` for N+1 runs), the hash slot is zero. The transaction is rejected even though it would succeed during actual execution in block N+1.

**Step 4 – The two sub-checks are inconsistent.**

| Check | Block number used | State used | Result for `proof_block_number = N − BUF + 1` |
|---|---|---|---|
| `validate_proof_block_number` | N+1 (inflated) | — | **PASS** |
| `validate_proof_block_hash` | — | Block N (stale) | **FAIL** (hash = 0) |

The inconsistency is the direct analog of the external report's `<=` vs `==` mismatch: one guard is evaluated with a looser context (inflated block number) while the correlated guard is evaluated with a tighter context (stale state), producing a contradictory outcome.

---

### Impact Explanation

**High. Mempool/gateway/RPC admission rejects valid transactions before sequencing.**

Any unprivileged user who submits an invoke V3 transaction carrying SNOS proof facts that reference block `N − STORED_BLOCK_HASH_BUFFER + 1` (the most recently allowed block under the inflated block number) will receive a gateway rejection ("Block hash mismatch") even though the transaction is fully valid for inclusion in block N+1. The transaction never reaches the mempool and must be resubmitted after the next block is committed.

---

### Likelihood Explanation

The condition is triggered whenever a user submits a proof-bearing transaction referencing the single block that is "allowed" by the inflated block-number check but whose hash is not yet in the gateway state. This is a deterministic, always-reachable boundary condition: the most recently allowed proof block is always exactly one block ahead of what the stale state can verify. Any client that constructs proof facts against the latest available block will hit this rejection.

---

### Recommendation

The two sub-checks must use a consistent view of the chain. The simplest fix is to apply `validate_proof_block_number` against the **non-incremented** block number (N) inside `validate_proof_facts`, matching the state that is actually available:

```rust
// In validate_proof_facts, pass the state's actual block number, not the
// gateway-inflated one, so the number check and hash check are consistent.
Self::validate_proof_block_number(
    proof_block_number,
    block_context.block_info.block_number.prev().unwrap_or(block_context.block_info.block_number),
)?;
```

Alternatively, `run_validate_entry_point` can simulate `pre_process_block` for block N+1 before running validation, so the state contains the hash for block `N − STORED_BLOCK_HASH_BUFFER + 1`. [5](#0-4) 

---

### Proof of Concept

1. Let the latest committed block be N (e.g., N = 20, `STORED_BLOCK_HASH_BUFFER` = 10).
2. Construct an invoke V3 transaction with `proof_block_number = N − STORED_BLOCK_HASH_BUFFER + 1 = 11` and the correct, non-zero block hash for block 11.
3. Submit to the gateway.
4. **Expected (correct) behavior**: the transaction is accepted, because when it executes in block N+1 = 21, `pre_process_block` will have stored the hash of block 11.
5. **Actual behavior**: `validate_proof_block_number` passes (11 ≤ (21) − 10 = 11), but `validate_proof_block_hash` reads `Felt::ZERO` from the block-N state for slot 11 and returns `InvalidProofFacts("Block hash mismatch …")`. The transaction is rejected at the gateway and never enters the mempool. [6](#0-5) [1](#0-0)

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
