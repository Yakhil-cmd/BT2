### Title
Incorrect `finish_tx` Operation Ordering in `EthereumStorageModel` Causes SELFDESTRUCT Storage Clears to Be Attributed to Wrong Transaction - (File: `basic_system/src/system_implementation/ethereum_storage_model/storage_model.rs`)

### Summary

In `EthereumStorageModel::finish_tx`, `storage_cache.finish_tx()` (which advances the transaction ID counter) is called **before** `account_cache.finish_tx(&mut self.storage_cache)` (which performs SELFDESTRUCT storage clears via `clear_state_impl`). This is the reverse of the correct ordering used in the parallel `FlatTreeWithAccountsUnderHashesStorageModel`. As a result, SELFDESTRUCT-triggered storage clears are attributed to the wrong (next) transaction, causing incorrect pubdata accounting and potential forward-execution/proving divergence.

### Finding Description

**Root cause — wrong ordering in `EthereumStorageModel::finish_tx`:** [1](#0-0) 

```rust
fn finish_tx(&mut self) -> Result<(), InternalError> {
    self.storage_cache.finish_tx()?;      // ← increments current_tx_id: N → N+1
    self.preimages_cache.finish_tx()?;
    self.account_cache.finish_tx(&mut self.storage_cache)?;  // ← calls clear_state_impl under tx N+1
    Ok(())
}
```

`storage_cache.finish_tx()` delegates to `GenericPubdataAwarePlainStorage::finish_tx`, whose sole effect is incrementing `current_tx_id`: [2](#0-1) 

After that increment, `account_cache.finish_tx` runs and calls `storage.clear_state_impl(key)` for every account marked for deconstruction (SELFDESTRUCT): [3](#0-2) 

The comment `"must clear state for code deconstruction in same TX"` documents the invariant that this write must occur within the same transaction — an invariant that is violated because `current_tx_id` has already been advanced.

**Correct ordering in the parallel implementation:**

`FlatTreeWithAccountsUnderHashesStorageModel` performs the same operations in the correct order — account cleanup first, then storage counter advance: [4](#0-3) 

```rust
fn finish_tx(&mut self) -> Result<(), InternalError> {
    self.account_data_cache.finish_tx(&mut self.storage_cache)?;  // cleanup first
    self.storage_cache.finish_tx()?;                               // then advance tx ID
    self.preimages_cache.finish_tx()
}
```

### Impact Explanation

`current_tx_id` in `GenericPubdataAwarePlainStorage` is used to determine whether a storage slot was first written in the current transaction (for pubdata accounting). When `clear_state_impl` writes happen after `finish_tx()` has incremented the counter to N+1, those writes are attributed to transaction N+1 instead of N. Consequences:

- **Pubdata undercounting for tx N**: the SELFDESTRUCT storage clears are not counted in tx N's pubdata, so the sequencer underestimates pubdata for that transaction.
- **Pubdata overcounting for tx N+1**: the clears appear as "new writes" in tx N+1, inflating its pubdata cost.
- **Forward-execution / proving divergence**: the prover, which independently recomputes pubdata attribution, will disagree with the sequencer's accounting, causing a state-root or pubdata-commitment mismatch — a critical integrity failure.

### Likelihood Explanation

The trigger path is straightforward and requires no privileged access: deploy a contract and have it call `SELFDESTRUCT` within the same transaction (constructor SELFDESTRUCT or a same-tx deploy-then-destruct pattern). This is a valid, reachable EVM operation. Any block containing such a transaction against the `EthereumStorageModel` path will exhibit the bug.

### Recommendation

Swap the call order in `EthereumStorageModel::finish_tx` to match `FlatTreeWithAccountsUnderHashesStorageModel`:

```rust
fn finish_tx(&mut self) -> Result<(), InternalError> {
    // Perform account-level cleanup (SELFDESTRUCT clears) BEFORE advancing tx ID
    self.account_cache.finish_tx(&mut self.storage_cache)?;
    self.storage_cache.finish_tx()?;
    self.preimages_cache.finish_tx()?;
    Ok(())
}
```

This ensures `clear_state_impl` writes are attributed to the correct transaction, preserving the documented invariant and matching the ordering in the flat storage model.

### Proof of Concept

1. Submit a transaction that deploys a contract whose constructor immediately calls `SELFDESTRUCT` (sending ETH to itself or a beneficiary).
2. The bootloader calls `finish_tx` on the `EthereumStorageModel` at end-of-transaction.
3. `storage_cache.finish_tx()` increments `current_tx_id` from N to N+1.
4. `account_cache.finish_tx` detects `is_marked_for_deconstruction = true` and calls `storage.clear_state_impl(key)` — now under tx ID N+1.
5. The pubdata for the SELFDESTRUCT storage clears is attributed to tx N+1 instead of tx N.
6. The prover, computing pubdata independently with the correct ordering, produces a different pubdata commitment, causing a forward-execution/proving divergence.

### Citations

**File:** basic_system/src/system_implementation/ethereum_storage_model/storage_model.rs (L463-468)
```rust
    fn finish_tx(&mut self) -> Result<(), InternalError> {
        self.storage_cache.finish_tx()?;
        self.preimages_cache.finish_tx()?;
        self.account_cache.finish_tx(&mut self.storage_cache)?;
        Ok(())
    }
```

**File:** basic_system/src/system_implementation/caches/generic_pubdata_aware_plain_storage.rs (L108-110)
```rust
    pub fn finish_tx(&mut self) {
        self.current_tx_id.0 += 1;
    }
```

**File:** basic_system/src/system_implementation/ethereum_storage_model/caches/account_cache.rs (L825-828)
```rust
                    storage
                        .slot_values
                        .clear_state_impl(key)
                        .expect("must clear state for code deconstruction in same TX");
```

**File:** basic_system/src/system_implementation/flat_storage_model/mod.rs (L519-523)
```rust
    fn finish_tx(&mut self) -> Result<(), zk_ee::system::errors::internal::InternalError> {
        self.account_data_cache.finish_tx(&mut self.storage_cache)?;
        self.storage_cache.finish_tx()?;
        self.preimages_cache.finish_tx()
    }
```
