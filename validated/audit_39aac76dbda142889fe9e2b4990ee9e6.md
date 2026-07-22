### Title
Gateway Proof-Facts Block-Number Check Uses `unchecked_next()` Block While State Remains at Previous Block, Causing Systematic False Rejection of Valid Client-Side-Proving Transactions - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`run_validate_entry_point` advances the block number by one (`block_info.block_number.unchecked_next()`) before building the `BlockContext` passed to blockifier validation, but the underlying state reader is still anchored to the latest committed block N. The `validate_proof_block_number` check therefore permits proof facts referencing block `N − 9` (i.e., `current − STORED_BLOCK_HASH_BUFFER` where current = `N + 1`), yet `validate_proof_block_hash` reads the stored block-hash from state at block N, where only hashes for blocks `0 … N − 10` have been written. The hash for block `N − 9` is `Felt::ZERO` in that state, so every well-formed proof referencing the most-recent allowed block is rejected with "Block hash mismatch" at the gateway, even though the same transaction would pass blockifier execution in block `N + 1` (where the OS writes the hash for `N − 9` during `pre_process_block`).

### Finding Description

**Step 1 – Block context construction in the gateway**

`run_validate_entry_point` fetches the latest committed block info and increments its block number:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();   // N → N+1
let block_context = BlockContext::new(block_info, …);
``` [1](#0-0) 

The state reader, however, is created from the **latest committed block N**:

```rust
let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();
// …
let state = CachedState::new(state_reader_and_contract_manager);
``` [2](#0-1) 

**Step 2 – Proof-block-number check uses the incremented block number**

`validate_proof_block_number` computes the maximum allowed proof block as `current_block_number − STORED_BLOCK_HASH_BUFFER`:

```rust
let max_allowed =
    current_block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER)…;
if proof_block_number > max_allowed { … }
``` [3](#0-2) 

With `current_block_number = N + 1`, `max_allowed = N − 9`. A proof referencing block `N − 9` passes this check.

**Step 3 – Proof-block-hash check reads from state at block N**

`validate_proof_block_hash` reads the stored hash from the state:

```rust
let stored_block_hash = state
    .get_storage_at(block_hash_contract_address, StorageKey::from(proof_block_number))?;
if stored_block_hash != proof_block_hash { … "Block hash mismatch" … }
``` [4](#0-3) 

**Step 4 – The OS only writes block `N − 9`'s hash when processing block `N + 1`**

The OS writes `block_number − STORED_BLOCK_HASH_BUFFER` during `pre_process_block`:

```
tempvar old_block_number = block_context.block_info_for_execute.block_number -
    STORED_BLOCK_HASH_BUFFER;
``` [5](#0-4) 

After block N is committed, storage contains hashes for blocks `0 … N − 10`. Block `N − 9`'s hash is written only when block `N + 1` is processed. `STORED_BLOCK_HASH_BUFFER = 10` is the constant governing this window: [6](#0-5) 

**The inconsistency:** The number check uses `N + 1` (permitting proof referencing `N − 9`), but the hash check reads from state at `N` where `stored_hash[N − 9] = Felt::ZERO`. The non-zero proof hash never matches zero, so the transaction is rejected with "Block hash mismatch."

### Impact Explanation

Every Invoke V3 transaction carrying client-side proof facts that reference the most-recently-allowed block (`latest_committed − 9`) is **systematically rejected** at the gateway with a spurious "Block hash mismatch" error. The transaction is valid and would succeed if included in the next block, but the gateway's off-by-one inconsistency between the block number used for the range check and the state used for the hash check makes it impossible to submit such a transaction until one additional block is committed. This is a persistent, reproducible false rejection for a well-defined class of valid transactions.

Impact category: **High – Mempool/gateway/RPC admission rejects valid transactions before sequencing.**

### Likelihood Explanation

Any user of the client-side proving feature who generates a proof referencing the most recent allowed block (`latest − 9`) and submits it immediately will hit this rejection. The window is exactly one block wide and repeats every block. No special privileges or unusual conditions are required; a standard Invoke V3 transaction with valid proof facts is sufficient to trigger it.

### Recommendation

Replace the incremented block number with the actual latest committed block number when computing `max_allowed` inside `validate_proof_block_number`, so the number check is consistent with the state available to the hash check:

```rust
// In run_validate_entry_point, keep block_number as-is for the proof-facts check,
// or pass the pre-increment block number separately to validate_proof_facts.
```

Alternatively, derive `max_allowed` from `current_block_number − 1` (i.e., the actual latest committed block) when the validation is running in gateway context, ensuring the number check never permits a block whose hash is not yet present in the state snapshot.

### Proof of Concept

Let `N = 20` (latest committed block). `STORED_BLOCK_HASH_BUFFER = 10`.

1. State at block 20 contains stored hashes for blocks 0–10.
2. User generates a proof referencing block 11 (= 20 − 9), which will be valid in block 21.
3. User submits the Invoke V3 transaction to the gateway.
4. Gateway calls `run_validate_entry_point`:
   - `block_info.block_number = 21` (after `unchecked_next()`)
   - `max_allowed = 21 − 10 = 11` → proof block 11 passes the number check
   - `stored_hash[11]` read from state at block 20 = `Felt::ZERO` (not yet written)
   - `proof_block_hash` (non-zero, correct hash of block 11) ≠ `Felt::ZERO`
   - Error: "Block hash mismatch for block 11. Proof block hash: 0x…, stored block hash: 0x0."
5. Transaction is rejected with `ValidateFailure`.
6. After block 21 is committed, state contains hash for block 11; the same transaction now passes.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-330)
```rust
        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L333-341)
```rust
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
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

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/os_utils.cairo (L52-53)
```text
    tempvar old_block_number = block_context.block_info_for_execute.block_number -
        STORED_BLOCK_HASH_BUFFER;
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/constants.cairo (L65-65)
```text
const STORED_BLOCK_HASH_BUFFER = 10;
```
