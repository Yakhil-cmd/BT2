### Title
Gateway `validate_proof_facts` uses `block_number.unchecked_next()` but state lacks the corresponding block hash — valid client-side-proving transactions spuriously rejected - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary
The gateway's stateful validator increments the block number by one (`block_info.block_number.unchecked_next()`) when building the `BlockContext` for proof-facts validation, but the underlying `CachedState` still reflects the committed chain tip (block N). This creates a structural one-block inconsistency: `validate_proof_block_number` permits proof block numbers up to `(N+1) − STORED_BLOCK_HASH_BUFFER = N−9`, while `validate_proof_block_hash` reads from a state that only contains hashes up to `N−10` (because `pre_process_block` for block N+1 has not yet run). Any Invoke V3 transaction whose `proof_facts` reference block `N−9` is therefore rejected with a spurious "Block hash mismatch" error, even though the same transaction would succeed when executed in block N+1.

### Finding Description

**Root cause — block number / state mismatch in `run_validate_entry_point`:**

In `run_validate_entry_point`, the gateway builds a `BlockContext` with the next block number but passes the current committed state:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();   // N → N+1
let block_context = BlockContext::new(block_info, ...);

let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager(); // state at N
let state = CachedState::new(state_reader_and_contract_manager);
let mut blockifier_validator =