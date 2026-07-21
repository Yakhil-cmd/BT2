### Title
Gateway Proof-Facts Block-Number Check Is One Block Ahead of the State It Reads, Causing Valid Transactions to Be Rejected - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`run_validate_entry_point` advances the block number by one (`block_info.block_number.unchecked_next()`) to simulate the next block, but the underlying state reader still reflects the committed state of the *current* latest block. `validate_proof_block_number` therefore permits a proof referencing block `latest − STORED_BLOCK_HASH_BUFFER + 1`, yet `validate_proof_block_hash` immediately rejects it with "block hash is zero" because `pre_process_block` for the next block has not yet run and has not yet written that hash. The transaction would be accepted by the blockifier when actually included in block `latest + 1`, but the gateway permanently rejects it one block too early.

### Finding Description

**Step 1 – Gateway inflates the block number.**

In `run_validate_entry_point`, the gateway builds a synthetic block context for the `__validate__` entry-point call:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();   // latest + 1
``` [1](#0-0) 

**Step 2 – `validate_proof_block_number` uses that inflated number.**

`validate_proof_facts` (called from `perform_pre_validation_stage`) computes:

```
max_allowed = current_block_number − STORED_BLOCK_HASH_BUFFER
            = (latest + 1) − 10
            = latest − 9
```

and accepts any `proof_block_number ≤ latest − 9`. [2](#0-1) 

**Step 3 – The state reader has not yet seen `pre_process_block` for block `latest + 1`.**

`pre_process_block` writes the hash of block `N − STORED_BLOCK_HASH_BUFFER` when processing block `N`. After block `latest` is committed, the state contains hashes for blocks `0 … latest − 10` only. The hash of block `latest − 9` is written only when block `latest + 1` is processed. [3](#0-2) 

**Step 4 – `validate_proof_block_hash` reads zero and rejects.**

```rust
let stored_block_hash = state.get_storage_at(block_hash_contract_address,
    StorageKey::from(proof_block_number))?;   // returns Felt::ZERO

if stored_block_hash != proof_block_hash {   // or the zero-hash guard fires first
    return Err(InvalidProofFacts("block hash is zero …"));
}
``` [4](#0-3) 

**Step 5 – The same transaction succeeds in the blockifier.**

When the sequencer actually executes block `latest + 1`, `pre_process_block` runs first and writes the hash of block `latest − 9`. The subsequent call to `validate_proof_facts` with `current_block_number = latest + 1` finds the hash and accepts the transaction. The gateway and the blockifier therefore disagree on the validity of the same transaction.

The boundary is exactly one block wide: a proof referencing block `B` is rejected at the gateway when the latest committed block is `B + STORED_BLOCK_HASH_BUFFER − 1`, but accepted when the latest committed block is `B + STORED_BLOCK_HASH_BUFFER`.

### Impact Explanation

**High – Mempool/gateway/RPC admission rejects valid transactions before sequencing.**

Any Invoke V3 transaction carrying `proof_facts` whose `block_number` equals `latest − STORED_BLOCK_HASH_BUFFER + 1` is rejected at the gateway with a spurious "block hash is zero" error. The transaction is genuinely valid for inclusion in the very next block. The user must wait for one additional block to be committed and then resubmit, which breaks the client-side proving UX and can cause proof-bearing transactions to be silently dropped by clients that do not retry.

### Likelihood Explanation

`STORED_BLOCK_HASH_BUFFER = 10`, so the affected block is always exactly 9 blocks behind the chain tip. Any client that generates a proof for a block and submits it promptly (within one block time) will hit this boundary. The condition is deterministic and reproducible on every block.

### Recommendation

Align the block number used for proof-facts validation with the block hashes actually present in the state. Either:

1. Do **not** advance the block number for the proof-facts check (use `latest` instead of `latest + 1`), or
2. Pre-apply the `pre_process_block` hash write for block `latest + 1` to the cached state before running `validate_proof_facts`.

Option 1 is simpler and consistent with the fact that the state reader reflects block `latest`.

### Proof of Concept

Let `STORED_BLOCK_HASH_BUFFER = 10` and the latest committed block be `N = 100`.

1. User generates a proof for block `91` (`= 100 − 10 + 1`).
2. User submits an Invoke V3 transaction with `proof_facts.block_number = 91`.
3. Gateway calls `run_validate_entry_point` with `block_info.block_number = 101`.
4. `validate_proof_block_number(91, 101)` → `max_allowed = 91` → **passes**.
5. `validate_proof_block_hash` reads `get_storage_at(block_hash_contract, key=91)` → `Felt::ZERO` (not yet written).
6. Returns `Err(InvalidProofFacts("Proof block hash is zero for block 91."))` → **gateway rejects**.
7. Sequencer commits block 101; `pre_process_block` writes `hash(91)` to storage.
8. User resubmits the same transaction; gateway now uses `block_number = 102`, `max_allowed = 92`; hash of block 91 is now in state → **accepted**.

The transaction was valid for block 101 but was rejected at step 6.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-324)
```rust
        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L268-286)
```rust
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
