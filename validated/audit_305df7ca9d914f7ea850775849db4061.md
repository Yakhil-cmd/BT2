Now I have all the information needed to evaluate this question. Let me trace the exact data flow.

### Title
Gateway `validate_proof_facts` Off-by-One Rejects Valid Proof-Carrying Invoke Transactions — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`run_validate_entry_point` advances the block number by one (`unchecked_next()`) before building the block context, making `current_block_number = latest + 1`. `validate_proof_block_number` therefore permits `proof_block_number = latest + 1 − STORED_BLOCK_HASH_BUFFER`. However, the gateway state is still at tip `latest`, which only contains stored block hashes up to `latest − STORED_BLOCK_HASH_BUFFER`. The hash for block `latest + 1 − STORED_BLOCK_HASH_BUFFER` is not yet written to state, so `get_storage_at` returns `Felt::ZERO`, and `validate_proof_block_hash` rejects the transaction with "Block hash mismatch". A legitimate user who constructs a proof referencing the most-recently-allowed block (as advertised by the block-number check) has their valid transaction rejected at gateway admission.

---

### Finding Description

**Step 1 — Block number is advanced before validation.**

In `run_validate_entry_point`:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();   // latest → latest+1
``` [1](#0-0) 

The block context passed to `perform_pre_validation_stage` therefore has `block_number = latest + 1`.

**Step 2 — Block-number check uses the advanced value.**

`validate_proof_block_number` computes:

```
max_allowed = current_block_number − STORED_BLOCK_HASH_BUFFER
            = (latest + 1) − 10
            = latest − 9
```

A proof with `proof_block_number = latest − 9` satisfies `proof_block_number ≤ max_allowed` and passes. [2](#0-1) 

**Step 3 — State only has hashes up to `latest − 10`.**

`pre_process_block` writes the hash of block `N − STORED_BLOCK_HASH_BUFFER` when processing block `N`. After block `latest` is committed, the block-hash contract holds entries for blocks `0 … latest − 10`. Block `latest − 9` has no entry yet; it will be written when block `latest + 1` is processed. [3](#0-2) 

`STORED_BLOCK_HASH_BUFFER = 10`: [4](#0-3) 

**Step 4 — Hash lookup returns `Felt::ZERO`, triggering rejection.**

`validate_proof_block_hash` reads:

```rust
let stored_block_hash = state.get_storage_at(
    block_hash_contract_address,
    StorageKey::from(proof_block_number),   // latest − 9, not yet stored
)?;
if stored_block_hash != proof_block_hash {
    return Err(InvalidProofFacts("Block hash mismatch …"));
}
``` [5](#0-4) 

Because the slot is uninitialised, `stored_block_hash = Felt::ZERO`. The user's proof carries the real (non-zero) hash of block `latest − 9`, so the comparison fails and the transaction is rejected.

---

### Impact Explanation

A user who follows the block-number bound advertised by `validate_proof_block_number` (i.e., uses `proof_block_number = latest + 1 − STORED_BLOCK_HASH_BUFFER`) submits a cryptographically valid proof-carrying Invoke V3 transaction that is unconditionally rejected at gateway admission with `ValidateFailure / InvalidProofFacts`. The transaction never reaches the mempool. This matches the allowed impact scope: **High — gateway admission rejects a valid transaction before sequencing**.

---

### Likelihood Explanation

Any client that queries the gateway's current block number, computes `max_allowed = (tip + 1) − STORED_BLOCK_HASH_BUFFER` (mirroring the gateway's own logic), and uses that as `proof_block_number` will trigger the rejection. The window is exactly one block wide (the single block between `latest − 10` and `latest − 9`), but it is persistent: it exists for every block until the next block is committed. A well-intentioned client trying to use the freshest allowed proof block will always land in this window.

---

### Recommendation

Remove the off-by-one in the proof-facts block-number check. Either:

1. **Do not advance the block number before calling `validate_proof_block_number`** — pass `latest` (not `latest + 1`) to `validate_proof_block_number` while keeping `unchecked_next()` only for the execution context that actually needs it; or
2. **Tighten `validate_proof_block_number` by one** — compute `max_allowed = current_block_number − STORED_BLOCK_HASH_BUFFER − 1` so the allowed range matches what the state actually contains.

Option 1 is cleaner: split the block context construction so that `block_info.block_number` is advanced only for the fields that require it (e.g., `validate_rounding_consts`), while `validate_proof_facts` receives the unadvanced `latest`.

---

### Proof of Concept

```rust
// Pseudocode unit test over perform_pre_validation_stage
let latest: u64 = 100;
// Gateway sets current_block_number = latest + 1 = 101
let mut block_context = BlockContext::create_for_account_testing();
block_context.block_info.block_number = BlockNumber(latest + 1);

// State contains hashes only up to latest - STORED_BLOCK_HASH_BUFFER = 90
// Block 91 (= latest + 1 - STORED_BLOCK_HASH_BUFFER) is NOT stored
let mut state = test_state_with_block_hashes_up_to(latest - STORED_BLOCK_HASH_BUFFER);

// User constructs proof referencing block 91 with its real hash
let proof_block_number = latest + 1 - STORED_BLOCK_HASH_BUFFER; // 91
let proof_facts = proof_facts_for_block(proof_block_number, real_hash_of_block_91);

let tx = invoke_tx_with_default_flags(invoke_tx_args! { proof_facts, .. });
let tx_context = block_context.to_tx_context(&tx);

// Expected: Ok(()) — proof is valid and block number passes the check
// Actual:   Err(InvalidProofFacts("Block hash mismatch …"))
//           because state has no entry for block 91
let result = tx.perform_pre_validation_stage(&mut state, &tx_context);
assert_matches!(result, Ok(())); // FAILS
```

The test `proof_facts_with_max_allowed_block` in the existing test suite uses `CURRENT_BLOCK_NUMBER − STORED_BLOCK_HASH_BUFFER` directly (without the `+1` offset), so it does not exercise the gateway's `unchecked_next()` path and does not catch this bug. [6](#0-5)

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

**File:** crates/blockifier/src/blockifier/block.rs (L18-33)
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
```

**File:** crates/blockifier/src/abi/constants.rs (L38-39)
```rust
// The block number -> block hash mapping is written for the current block number minus this number.
pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
```

**File:** crates/blockifier/src/transaction/account_transactions_test.rs (L2237-2247)
```rust
fn proof_facts_with_max_allowed_block() -> ProofFacts {
    let block_number = CURRENT_BLOCK_NUMBER - STORED_BLOCK_HASH_BUFFER;
    create_valid_proof_facts_for_testing()
        .try_into()
        .map(|mut snos: SnosProofFacts| {
            snos.block_number = BlockNumber(block_number);
            snos.block_hash = test_block_hash(block_number);
            snos_to_proof_facts(snos)
        })
        .unwrap()
}
```
