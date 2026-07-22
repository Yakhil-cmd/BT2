The code is clear. Let me verify the `is_contract_class_declared` function and the `SyncStateReader` path to complete the analysis.

### Title
Missing `is_declared` Guard for Cairo 0 Classes in `ExecutionStateReader::get_compiled_class` — (`crates/apollo_rpc_execution/src/state_reader.rs`)

---

### Summary

`ExecutionStateReader::get_compiled_class` enforces a state-number–aware declaration check for V1 (Sierra/CASM) classes when the `class_manager_handle` path is active, but **unconditionally omits that check for V0 (deprecated/Cairo 0) classes**. An unprivileged caller can supply a `class_hash` that resolves to a V0 entry in the class manager but was never declared (or was declared only in a later block) at the requested `state_number`, causing the function to return a `RunnableCompiledClass::V0` for an undeclared class. The acknowledged TODO comment confirms the gap is known but unresolved.

---

### Finding Description

In `ExecutionStateReader::get_compiled_class`, when `self.class_manager_handle` is `Some`, the code branches on the returned `ContractClass` variant:

```
ContractClass::V1(casm_contract_class) => {
    let is_declared = is_contract_class_declared(
        &self.storage_reader.begin_ro_txn()...,
        &class_hash,
        self.state_number,
    )?;
    if is_declared {
        Ok(RunnableCompiledClass::V1(casm_contract_class.try_into()?))
    } else {
        Err(StateError::UndeclaredClassHash(class_hash))   // ← enforced
    }
}
// TODO(shahak): Verify cairo0 as well after get_class_definition_block_number is fixed.
ContractClass::V0(deprecated_contract_class) => {
    Ok(RunnableCompiledClass::V0(deprecated_contract_class.try_into()?))  // ← no check
}
``` [1](#0-0) 

The V1 arm calls `is_contract_class_declared`, which queries `get_class_definition_block_number` and verifies `state_number.is_after(block_number)`: [2](#0-1) 

The V0 arm has no equivalent guard. The class manager is a global artifact store with no block-level state awareness; it holds every deprecated class ever synced, regardless of whether it was declared at the `state_number` being queried.

The safe fallback path (no `class_manager_handle`) is correct: `get_contract_class` calls `get_deprecated_class_definition_at(state_number, class_hash)`, which is state-number–scoped: [3](#0-2) 

The gateway's `SyncStateReader` is also correct: it calls `is_class_declared_at(block_number, class_hash)` for **all** classes before fetching from the class manager: [4](#0-3) 

Only `ExecutionStateReader` (used by the RPC execution layer) is missing the V0 guard.

---

### Impact Explanation

`ExecutionStateReader` is the state reader used by `execute_transactions`, which backs `estimate_fee`, `simulate_transactions`, and related RPC endpoints: [5](#0-4) 

An attacker can submit an `starknet_estimateFee` or `starknet_simulateTransactions` request targeting a historical `state_number` (e.g., block N−1) and include a transaction that issues a `library_call` syscall with a `class_hash` of a deprecated class that:
- exists in the class manager (synced from block N or later), and
- was **not** declared at the requested `state_number`.

Blockifier calls `get_compiled_class(class_hash)` during execution. The class manager returns `ContractClass::V0(...)`. The missing guard causes the function to return `Ok(RunnableCompiledClass::V0(...))` instead of `Err(StateError::UndeclaredClassHash(...))`. The undeclared class is executed, and the RPC endpoint returns an authoritative-looking but wrong execution trace and fee estimate.

Impact: **High — RPC execution, fee estimation, tracing, or simulation returns an authoritative-looking wrong value.**

---

### Likelihood Explanation

- The `class_manager_handle` is `Some` in production RPC execution deployments.
- The `library_call` syscall accepts an arbitrary caller-supplied `class_hash`, making the trigger fully unprivileged.
- The class manager accumulates deprecated classes from all synced blocks; any class declared in a block after the queried `state_number` is a candidate.
- The TODO comment confirms the developers are aware the check is absent and deferred.

---

### Recommendation

Apply the same `is_contract_class_declared` guard to the V0 arm:

```rust
ContractClass::V0(deprecated_contract_class) => {
    let is_declared = is_contract_class_declared(
        &self.storage_reader.begin_ro_txn().map_err(storage_err_to_state_err)?,
        &class_hash,
        self.state_number,
    )
    .map_err(|e| StateError::StateReadError(e.to_string()))?;

    if is_declared {
        Ok(RunnableCompiledClass::V0(deprecated_contract_class.try_into()?))
    } else {
        Err(StateError::UndeclaredClassHash(class_hash))
    }
}
```

The TODO references a bug in `get_class_definition_block_number` for Cairo 0 classes. That underlying bug should be fixed first (or the check should use `get_deprecated_class_definition_at` directly, mirroring the fallback path), and then the guard should be added and the TODO removed.

---

### Proof of Concept

Construct a Rust integration test against `ExecutionStateReader`:

1. Create a storage with block 0 containing **no** deprecated class declarations.
2. Populate the class manager with a deprecated class under hash `H` (simulating a class synced from a future block).
3. Build an `ExecutionStateReader` with `state_number = right_after_block(0)` and `class_manager_handle = Some(...)`.
4. Call `state_reader.get_compiled_class(H)`.
5. **Expected (correct):** `Err(StateError::UndeclaredClassHash(H))`.
6. **Actual (buggy):** `Ok(RunnableCompiledClass::V0(...))` — the undeclared class is returned without error. [6](#0-5)

### Citations

**File:** crates/apollo_rpc_execution/src/state_reader.rs (L121-141)
```rust
            return match contract_class {
                ContractClass::V1(casm_contract_class) => {
                    let is_declared = is_contract_class_declared(
                        &self.storage_reader.begin_ro_txn().map_err(storage_err_to_state_err)?,
                        &class_hash,
                        self.state_number,
                    )
                    .map_err(|e| StateError::StateReadError(e.to_string()))?;

                    if is_declared {
                        Ok(RunnableCompiledClass::V1(casm_contract_class.try_into()?))
                    } else {
                        Err(StateError::UndeclaredClassHash(class_hash))
                    }
                }
                // TODO(shahak): Verify cairo0 as well after get_class_definition_block_number is
                // fixed.
                ContractClass::V0(deprecated_contract_class) => {
                    Ok(RunnableCompiledClass::V0(deprecated_contract_class.try_into()?))
                }
            };
```

**File:** crates/apollo_rpc_execution/src/execution_utils.rs (L53-62)
```rust
pub(crate) fn is_contract_class_declared(
    txn: &StorageTxn<'_, RO>,
    class_hash: &ClassHash,
    state_number: StateNumber,
) -> Result<bool, ExecutionUtilsError> {
    Ok(txn
        .get_state_reader()?
        .get_class_definition_block_number(class_hash)?
        .is_some_and(|block_number| state_number.is_after(block_number)))
}
```

**File:** crates/apollo_rpc_execution/src/execution_utils.rs (L85-92)
```rust
    let Some(deprecated_class) =
        txn.get_state_reader()?.get_deprecated_class_definition_at(state_number, class_hash)?
    else {
        return Ok(None);
    };
    Ok(Some(RunnableCompiledClass::V0(
        CompiledClassV0::try_from(deprecated_class).map_err(ExecutionUtilsError::ProgramError)?,
    )))
```

**File:** crates/apollo_gateway/src/sync_state_reader.rs (L77-99)
```rust
    fn get_contract_class_from_client(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        let is_class_declared = self
            .runtime
            .block_on(self.state_sync_client.is_class_declared_at(self.block_number, class_hash))
            .map_err(|e| StateError::StateReadError(e.to_string()))?;

        if !is_class_declared {
            return Err(StateError::UndeclaredClassHash(class_hash));
        }

        let contract_class = self
            .runtime
            .block_on(self.class_manager_client.get_executable(class_hash))
            .map_err(|e| StateError::StateReadError(e.to_string()))?
            .unwrap_or_else(|| {
                panic!(
                    "Class with hash {class_hash:?} doesn't appear in class manager even though \
                     it was declared"
                )
            });

        Ok(contract_class)
    }
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L692-699)
```rust
    // The starknet state will be from right before the block in which the transactions should run.
    let mut cached_state = CachedState::new(ExecutionStateReader {
        storage_reader: storage_reader.clone(),
        state_number,
        maybe_pending_data: maybe_pending_data.clone(),
        missing_compiled_class: Cell::new(None),
        class_manager_handle,
    });
```
