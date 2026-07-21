Let me look at the state reader setup and how `pre_process_block` interacts with the gateway's state.

Now I have all the information needed for a complete analysis. Let me trace the exact execution path.

**The exact data flow:**

1. `run_validate_entry_point` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` line 324:
   ```rust
   block_info.block_number = block_info.block_number.unchecked_next();
   ```
   → `current_block_number = N + 1`

2. `validate_proof_block_number` (`crates/blockifier/src/transaction/account_transaction.rs` line 244):
   ```rust
   let max_allowed = current_block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER)
   ```
   → `max_allowed = (N+1) - 10 = N - 9`. So `proof_block_number = N - 9` **passes**.

3. The state reader is obtained via `get_blockifier_state_reader_and_gateway_fixed_block_from_latest_block()` (`crates/apollo_gateway/src/sync_state_reader.rs` line 531):
   ```rust
   let latest_block_number = self.shared_state_sync_client.get_latest_block_number().await?;
   let blockifier_state_reader = SyncStateReader::from_number(..., latest_block_number, ...);
   ```
   → State is at block **N** (not N+1). This state has block hashes stored for blocks `0` through `N-10` only (each block `k` writes the hash for block `k - STORED_BLOCK_HASH_BUFFER` via `pre_process_block`).

4. `validate_proof_block_hash` (`crates/blockifier/src/transaction/account_transaction.rs` line 278):
   ```rust
   let stored_block_hash = state.get_storage_at(block_hash_contract_address, StorageKey::from(proof_block_number))?;
   if stored_block_hash != proof_block_hash { return Err(...) }
   ```
   → For `proof_block_number = N-9`, `stored_block_hash = Felt::ZERO` (not yet written). The user's legitimate `proof_block_hash` is non-zero → **"Block hash mismatch" error → transaction rejected**.

5. During actual execution of block N+1, `pre_process_block` writes the hash for block `(N+1) - 10 = N-9` **before** transactions execute, so the same transaction would pass both checks.

---

### Title
Gateway Rejects Valid Proof-Bearing Invoke Transactions at the `proof_block_number = latest - STORED_BLOCK_HASH_BUFFER + 1` Boundary — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary
`run_validate_entry_point` advances the block number by one (`unchecked_next()`) for the block-number range check, but reads block-hash storage from the **committed** state at block N. This creates a one-block gap: `validate_proof_block_number` accepts `proof_block_number = N - 9`, but `validate_proof_block_hash` reads `Felt::ZERO` for that slot because `pre_process_block` for block N+1 has not yet run. A legitimate user holding a valid proof for block `N - 9` is permanently rejected at the gateway until the chain advances one more block.

### Finding Description

`run_validate_entry_point` builds the block context with:

```rust
block_info.block_number = block_info.block_number.unchecked_next();
``` [1](#0-0) 

This makes `current_block_number = N + 1`, so `validate_proof_block_number` computes `max_allowed = (N+1) - STORED_BLOCK_HASH_BUFFER = N - 9` and accepts `proof_block_number = N - 9`. [2](#0-1) 

However, the state reader is obtained from the **latest committed block N** — not from a state that includes the pending `pre_process_block` writes for block N+1:

```rust
let latest_block_number = self.shared_state_sync_client.get_latest_block_number().await?;
let blockifier_state_reader = SyncStateReader::from_number(..., latest_block_number, ...);
``` [3](#0-2) 

The block-hash contract at block N contains entries for blocks `0` through `N - 10` only. The entry for block `N - 9` is written by `pre_process_block` when block N+1 is **built**, not when it is validated at the gateway:

```rust
state.set_storage_at(block_hash_contract_address, StorageKey::from(number.0), hash.0)?;
``` [4](#0-3) 

Consequently, `validate_proof_block_hash` reads `Felt::ZERO` for key `N - 9` and fails with `"Block hash mismatch"` even though the user supplied the correct, non-zero hash:

```rust
let stored_block_hash = state.get_storage_at(block_hash_contract_address, StorageKey::from(proof_block_number))?;
if stored_block_hash != proof_block_hash { return Err(...) }
``` [5](#0-4) 

The same transaction would pass both checks during actual execution of block N+1 because the OS calls `pre_process_block` before `execute_transactions`: [6](#0-5) 

### Impact Explanation

A legitimate user who holds a valid SNOS proof for block `N - 9` and submits an Invoke V3 transaction when the latest committed block is `N` will have their transaction rejected at the gateway with a spurious `"Block hash mismatch"` error. The transaction is valid for the next block but is denied admission to the mempool. This is a **High** impact gateway admission issue: valid transactions are rejected before sequencing.

### Likelihood Explanation

The boundary is hit deterministically whenever a user targets the most recent allowed proof block (`latest - STORED_BLOCK_HASH_BUFFER + 1`). Any client-side proving SDK that picks the freshest eligible block will hit this condition on every submission attempt until the chain advances one more block. The condition is reproducible and requires no special privileges.

### Recommendation

Align the two checks so they use the same effective block number. The simplest fix is to use `N` (not `N + 1`) as `current_block_number` inside `validate_proof_block_number`, or equivalently to cap `max_allowed` at `N - STORED_BLOCK_HASH_BUFFER` (i.e., subtract one extra from the `unchecked_next()` value). Alternatively, apply the `pre_process_block` write to the gateway's cached state before running `validate_proof_facts`, mirroring what the batcher does at block-build time.

### Proof of Concept

```
latest committed block = N = 19, STORED_BLOCK_HASH_BUFFER = 10

Gateway block context:  current = unchecked_next(19) = 20
validate_proof_block_number: max_allowed = 20 - 10 = 10  → proof_block_number=10 PASSES

Gateway state reader:   state at block 19
  block-hash contract storage: keys 0..9 populated, key 10 = Felt::ZERO
  (key 10 is written only when block 20 is built)

validate_proof_block_hash(proof_block_hash=hash(10), proof_block_number=10):
  stored = state.get_storage_at(contract, key=10) = Felt::ZERO
  Felt::ZERO != hash(10)  → ERROR "Block hash mismatch for block 10"
  → Transaction REJECTED

Same transaction during execution of block 20:
  pre_process_block writes key=10 → hash(10)
  validate_proof_block_hash: stored = hash(10) == proof_block_hash  → PASSES
  → Transaction VALID
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-325)
```rust
        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L244-257)
```rust
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
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L278-286)
```rust
        let stored_block_hash = state
            .get_storage_at(block_hash_contract_address, StorageKey::from(proof_block_number))?;

        if stored_block_hash != proof_block_hash {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "Block hash mismatch for block {proof_block_number}. Proof block hash: \
                 {proof_block_hash}, stored block hash: {stored_block_hash}."
            )));
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

**File:** crates/blockifier/src/blockifier/block.rs (L26-33)
```rust
    if let Some(BlockHashAndNumber { number, hash }) = old_block_number_and_hash {
        let block_hash_contract_address =
            os_constants.os_contract_addresses.block_hash_contract_address();
        let block_number_as_storage_key = StorageKey::from(number.0);
        state.set_storage_at(block_hash_contract_address, block_number_as_storage_key, hash.0)?;
    } else if should_block_hash_be_provided {
        return Err(StateError::OldBlockHashNotProvided);
    }
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/os.cairo (L217-225)
```text
    with contract_state_changes, contract_class_changes {
        pre_process_block(block_context=block_context);
    }

    // Execute transactions.
    let outputs = initial_carried_outputs;
    with contract_state_changes, contract_class_changes, outputs {
        execute_transactions(block_context=block_context);
    }
```
