### Title
Missing Declaration Check for Cairo V0 Classes in `ExecutionStateReader::get_compiled_class` When Class Manager Is Active - (`crates/apollo_rpc_execution/src/state_reader.rs`)

---

### Summary

When `class_manager_handle` is `Some`, `get_compiled_class` enforces a `is_contract_class_declared` guard for `ContractClass::V1` classes but **unconditionally returns `Ok`** for `ContractClass::V0` classes, regardless of whether the class is declared at the queried `state_number`. The TODO comment at the defect site explicitly acknowledges this omission.

---

### Finding Description

In `ExecutionStateReader::get_compiled_class`, the class-manager branch handles the two class variants asymmetrically:

```
ContractClass::V1  →  calls is_contract_class_declared(state_number)
                       returns Err(UndeclaredClassHash) if not declared ✓

ContractClass::V0  →  returns Ok(RunnableCompiledClass::V0(...)) unconditionally ✗
``` [1](#0-0) 

The `is_contract_class_declared` helper checks `get_class_definition_block_number` against `state_number.is_after(block_number)`, which is exactly the guard that is applied for V1 but skipped for V0. [2](#0-1) 

The class manager is a flat, state-number-agnostic store. It holds every V0 class that has ever been synced, regardless of when it was declared. [3](#0-2) 

The `class_manager_handle` field is passed through to `ExecutionStateReader` in both the `execute_call` and `execute_transactions` production paths, so the class-manager branch is reachable from live RPC simulation and fee-estimation endpoints. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

An RPC simulation or fee-estimation request that causes `get_compiled_class` to be called with a V0 `class_hash` that exists in the class manager but is **not yet declared at the queried `state_number`** will receive `Ok(RunnableCompiledClass::V0(...))` instead of `Err(UndeclaredClassHash)`. The blockifier then executes the undeclared class and returns a simulation trace, fee estimate, or call result as if the class were legitimately declared at that state. This is a wrong authoritative-looking value from the RPC simulation path, matching the **High** impact tier.

---

### Likelihood Explanation

**Preconditions required:**

1. `class_manager_handle` is `Some` (production sequencer node with class manager enabled).
2. A Cairo V0 class `C` is declared at block `N` and therefore present in the class manager.
3. An RPC simulation is issued at `state_number` < `N` (historical query before `C`'s declaration).
4. The simulated transaction triggers `get_compiled_class(C)` — most directly via a `library_call` syscall from a contract deployed before block `N`.

Conditions 1–3 are normal operational states. Condition 4 requires a contract that issues a `library_call` to `C`'s hash, which is a standard Cairo pattern. All four conditions are reachable by an unprivileged user who can observe on-chain data and submit RPC simulation requests.

---

### Recommendation

Apply the same `is_contract_class_declared` guard to the `ContractClass::V0` arm, mirroring the V1 logic. The TODO comment at lines 136–137 already identifies this as the intended fix pending a `get_class_definition_block_number` correction.

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

---

### Proof of Concept

**Setup:**
- Node running with `class_manager_handle = Some`.
- Cairo V0 class `C` declared at block `N`; class manager holds it.
- Contract `A` deployed at block `M < N`; its `__execute__` issues `library_call(C, selector, ...)`.

**Steps:**
1. Submit `starknet_simulateTransactions` targeting contract `A` at `block_id = N-1`.
2. Blockifier calls `get_compiled_class(C)` during the library call.
3. Class manager returns `ContractClass::V0(C)`.
4. The V0 arm at line 138–140 returns `Ok(RunnableCompiledClass::V0(...))` without checking `is_contract_class_declared`.
5. Simulation completes successfully and returns a trace/fee estimate as if `C` were declared at block `N-1`.

**Expected:** `Err(UndeclaredClassHash(C))`
**Actual:** `Ok(RunnableCompiledClass::V0(...))` — simulation executes the undeclared class. [6](#0-5)

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

**File:** crates/apollo_class_manager/src/class_manager.rs (L136-144)
```rust
    #[instrument(skip(self, class), ret, err)]
    pub fn add_deprecated_class(
        &mut self,
        class_id: ClassId,
        class: RawExecutableClass,
    ) -> ClassManagerResult<()> {
        self.classes.set_deprecated_class(class_id, class)?;
        Ok(())
    }
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L260-266)
```rust
    let mut cached_state = CachedState::new(ExecutionStateReader {
        storage_reader: storage_reader.clone(),
        state_number,
        maybe_pending_data: maybe_pending_data.clone(),
        missing_compiled_class: Cell::new(None),
        class_manager_handle,
    });
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L693-699)
```rust
    let mut cached_state = CachedState::new(ExecutionStateReader {
        storage_reader: storage_reader.clone(),
        state_number,
        maybe_pending_data: maybe_pending_data.clone(),
        missing_compiled_class: Cell::new(None),
        class_manager_handle,
    });
```
