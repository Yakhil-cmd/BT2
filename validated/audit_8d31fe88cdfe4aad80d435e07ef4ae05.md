### Title
`get_compiled_class_hash` Ignores `state_number` Bound, Returns Future-Block Compiled Class Hash in RPC Simulation — (`crates/apollo_rpc_execution/src/state_reader.rs`)

---

### Summary

`ExecutionStateReader::get_compiled_class_hash` calls `get_class_definition_block_number`, which is a raw key-value lookup with **no state_number guard**, then unconditionally reads the state diff at the returned block number. It never checks whether that block number falls within the queried state. This is inconsistent with every other state-bounded reader in the codebase and is **confirmed by an existing test that asserts the buggy behavior**.

---

### Finding Description

`get_class_definition_block_number` (storage layer) is a plain key-value lookup:

```rust
pub fn get_class_definition_block_number(
    &self,
    class_hash: &ClassHash,
) -> StorageResult<Option<BlockNumber>> {
    Ok(self.declared_classes_block_table.get(self.txn, class_hash)?)
}
```

It returns the block at which the class was written to storage, regardless of the caller's `state_number`. [1](#0-0) 

`get_compiled_class_hash` in `ExecutionStateReader` calls this, receives `block_number`, and immediately reads the state diff at that block — **without ever checking `block_number <= state_number.block_after()`**:

```rust
let maybe_block_number = self...get_class_definition_block_number(&class_hash)...?;
let Some(block_number) = maybe_block_number else { return Ok(CompiledClassHash::default()); };
// ← NO: if block_number > state_number.block_after(), this is a future block
let state_diff = self...get_state_diff(block_number)...?;
let compiled_class_hash = state_diff.class_hash_to_compiled_class_hash.get(&class_hash)...?;
Ok(*compiled_class_hash)
``` [2](#0-1) 

**Every correct peer implementation applies the state_number bound:**

- `get_class_definition_at` returns `None` when `state_number.is_before(block_number)`. [3](#0-2) 
- `get_contract_class` (used by `get_compiled_class`) returns `Ok(None)` for the same condition. [4](#0-3) 
- `get_compiled_class_hash_at` (storage layer) correctly uses `state_number.block_after()` as the upper bound. [5](#0-4) 
- `ApolloReader::get_compiled_class_hash` uses `get_compiled_class_hash_at` and is correct. [6](#0-5) 

**The existing test explicitly asserts the buggy behavior.** With `state_number = right_after_block(0)` and `class_hash0` declared at `BlockNumber(1)`:

```rust
// get_compiled_class correctly returns UndeclaredClassHash:
assert_matches!(state_reader0.get_compiled_class(class_hash0),
    Err(StateError::UndeclaredClassHash(_)));
// get_compiled_class_hash INCORRECTLY returns the future block's hash:
assert_eq!(state_reader0.get_compiled_class_hash(class_hash0).unwrap(), compiled_class_hash0);
``` [7](#0-6) 

The developers are aware of the underlying issue, as noted by the TODO comment:

```rust
// TODO(shahak): Verify cairo0 as well after get_class_definition_block_number is fixed.
``` [8](#0-7) 

---

### Impact Explanation

**Impact: High — RPC simulation/fee estimation returns an authoritative-looking wrong value.**

`ExecutionStateReader` is the state reader for the RPC execution path (`starknet_estimateFee`, `starknet_simulateTransactions`, `starknet_call` at historical blocks). When a user queries at block N-1 while class C was declared at block N (already in storage), `get_compiled_class_hash(C)` returns the compiled class hash H from block N instead of `CompiledClassHash::default()`.

The concrete corruption path through `CachedState`:

1. `CachedState::get_compiled_class_hash` reads the initial value from the underlying `ExecutionStateReader` and caches it as H (wrong; should be default). [9](#0-8) 
2. `try_declare` (correctly) uses `get_compiled_class` — not `get_compiled_class_hash` — to check if the class is already declared, so the declaration proceeds. [10](#0-9) 
3. `set_compiled_class_hash(C, H_tx)` is called with the compiled class hash from the transaction.
4. The state diff is computed as `(initial=H) → (final=H_tx)`. If `H == H_tx` (the user is re-declaring the same class with the same compiled class hash), the diff shows **no change** for `compiled_class_hashes`, producing a wrong simulation state diff.
5. If `H ≠ H_tx`, the diff shows a spurious "change" from a non-zero initial value, which is also wrong.

The `perform_pre_validation_stage` for Declare transactions does **not** call `get_compiled_class_hash` (it only checks nonce, fee bounds, and proof facts), so gateway/mempool admission is unaffected. [11](#0-10) 

The gateway stateful path always uses the latest block state, where all declared classes are correctly visible, so the bug does not affect actual transaction admission or sequencing.

---

### Likelihood Explanation

Any unprivileged user can trigger this by calling `starknet_simulateTransactions` or `starknet_estimateFee` at any historical block with a DeclareV2/V3 transaction for a class that was declared in a later block. No special privileges are required. The scenario is routine: a user simulating a declare at a past block while the class is already in storage.

---

### Recommendation

Add the missing state_number bound in `get_compiled_class_hash`, mirroring the pattern used in `get_class_definition_at` and `get_contract_class`:

```rust
let Some(block_number) = maybe_block_number else {
    return Ok(CompiledClassHash::default());
};
// Add this guard:
if self.state_number.is_before(block_number) {
    return Ok(CompiledClassHash::default());
}
```

Alternatively, replace the two-step `get_class_definition_block_number` + `get_state_diff` lookup with the already-correct `get_compiled_class_hash_at(state_number, &class_hash)` from the storage layer, which already applies the bound correctly. [5](#0-4) 

---

### Proof of Concept

The existing test at line 186 of `state_reader_test.rs` already demonstrates the bug:

```rust
// state_number0 = right_after_block(0)
// class_hash0 declared at BlockNumber(1) (future block)
assert_eq!(
    state_reader0.get_compiled_class_hash(class_hash0).unwrap(),
    compiled_class_hash0  // returns future block's hash — WRONG
);
assert_matches!(
    state_reader0.get_compiled_class(class_hash0),
    Err(StateError::UndeclaredClassHash(_))  // correctly returns undeclared
);
``` [7](#0-6) 

To confirm the state-diff corruption, a test can:
1. Build an `ExecutionStateReader` at `state_number = right_after_block(0)`.
2. Append a state diff with `class_hash_to_compiled_class_hash` at `BlockNumber(1)`.
3. Wrap in a `CachedState`, execute a DeclareV2 for the same class hash with the same compiled class hash.
4. Assert `to_state_diff().compiled_class_hashes` is empty (the bug causes the diff to show no change, hiding the declaration).

### Citations

**File:** crates/apollo_storage/src/state/mod.rs (L375-388)
```rust
    pub fn get_compiled_class_hash_at(
        &self,
        state_number: StateNumber,
        class_hash: &ClassHash,
    ) -> StorageResult<Option<CompiledClassHash>> {
        // State diff updates are indexed by the block_number at which they occurred.
        let block_number: BlockNumber = state_number.block_after();
        get_compiled_class_hash_at(
            block_number,
            class_hash,
            self.txn,
            &self.compiled_class_hash_table,
        )
    }
```

**File:** crates/apollo_storage/src/state/mod.rs (L472-474)
```rust
        if state_number.is_before(block_number) {
            return Ok(None);
        }
```

**File:** crates/apollo_storage/src/state/mod.rs (L499-504)
```rust
    pub fn get_class_definition_block_number(
        &self,
        class_hash: &ClassHash,
    ) -> StorageResult<Option<BlockNumber>> {
        Ok(self.declared_classes_block_table.get(self.txn, class_hash)?)
    }
```

**File:** crates/apollo_rpc_execution/src/state_reader.rs (L136-137)
```rust
                // TODO(shahak): Verify cairo0 as well after get_class_definition_block_number is
                // fixed.
```

**File:** crates/apollo_rpc_execution/src/state_reader.rs (L174-207)
```rust
        let maybe_block_number = self
            .storage_reader
            .begin_ro_txn()
            .map_err(storage_err_to_state_err)?
            .get_state_reader()
            .map_err(storage_err_to_state_err)?
            .get_class_definition_block_number(&class_hash)
            .map_err(storage_err_to_state_err)?;

        // Cairo 0 classes (and undeclared classes) do not have a compiled class hash.
        // According to the trait, return the default value.
        let Some(block_number) = maybe_block_number else {
            return Ok(CompiledClassHash::default());
        };

        let state_diff = self
            .storage_reader
            .begin_ro_txn()
            .map_err(storage_err_to_state_err)?
            .get_state_diff(block_number)
            .map_err(storage_err_to_state_err)?
            .ok_or(StateError::StateReadError(format!(
                "Inner storage error. Missing state diff at block {block_number}."
            )))?;

        let compiled_class_hash = state_diff
            .class_hash_to_compiled_class_hash
            .get(&class_hash)
            .ok_or(StateError::StateReadError(format!(
                "Inner storage error. Missing class declaration at block {block_number}, class \
                 {class_hash}."
            )))?;

        Ok(*compiled_class_hash)
```

**File:** crates/apollo_rpc_execution/src/execution_utils.rs (L69-71)
```rust
    match txn.get_state_reader()?.get_class_definition_block_number(class_hash)? {
        Some(block_number) if state_number.is_before(block_number) => return Ok(None),
        Some(_block_number) => {
```

**File:** crates/apollo_state_reader/src/apollo_state.rs (L243-254)
```rust
    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        let state_number = StateNumber(self.latest_block);
        match self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_compiled_class_hash_at(state_number, &class_hash))
        {
            Ok(Some(compiled_class_hash)) => Ok(compiled_class_hash),
            Ok(None) => Ok(CompiledClassHash::default()),
            Err(err) => Err(StateError::StateReadError(err.to_string())),
        }
    }
```

**File:** crates/apollo_rpc_execution/src/state_reader_test.rs (L181-186)
```rust
    let compiled_contract_class_after_block_0 = state_reader0.get_compiled_class(class_hash0);
    assert_matches!(
        compiled_contract_class_after_block_0, Err(StateError::UndeclaredClassHash(class_hash))
        if class_hash == class_hash0
    );
    assert_eq!(state_reader0.get_compiled_class_hash(class_hash0).unwrap(), compiled_class_hash0);
```

**File:** crates/blockifier/src/state/cached_state.rs (L204-216)
```rust
    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        let mut cache = self.cache.borrow_mut();

        if cache.get_compiled_class_hash(class_hash).is_none() {
            let compiled_class_hash = self.state.get_compiled_class_hash(class_hash)?;
            cache.set_compiled_class_hash_initial_value(class_hash, compiled_class_hash);
        }

        let compiled_class_hash = cache
            .get_compiled_class_hash(class_hash)
            .unwrap_or_else(|| panic!("Cannot retrieve '{class_hash:?}' from the cache."));
        Ok(*compiled_class_hash)
    }
```

**File:** crates/blockifier/src/transaction/transactions.rs (L393-407)
```rust
    match state.get_compiled_class(class_hash) {
        Err(StateError::UndeclaredClassHash(_)) => {
            // Class is undeclared; declare it.
            state.set_contract_class(class_hash, tx.contract_class().try_into()?)?;
            if let Some(compiled_class_hash) = compiled_class_hash {
                state.set_compiled_class_hash(class_hash, compiled_class_hash)?;
            }
            Ok(())
        }
        Err(error) => Err(error)?,
        Ok(_) => {
            // Class is already declared, cannot redeclare.
            Err(TransactionExecutionError::DeclareTransactionError { class_hash })
        }
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
