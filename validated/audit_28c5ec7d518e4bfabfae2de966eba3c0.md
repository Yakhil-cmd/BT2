Looking at the code in `state_reader.rs`, the asymmetry is real and confirmed by a developer TODO comment.

The code asymmetry is real and confirmed by a developer TODO. Let me verify the full picture before rendering a verdict.

The `get_compiled_class` function in `ExecutionStateReader` has two distinct branches when `class_manager_handle` is `Some`:

- **`ContractClass::V1`** (lines 122-134): calls `is_contract_class_declared(storage_reader, class_hash, state_number)` and returns `Err(UndeclaredClassHash)` if the class was not declared at `state_number`.
- **`ContractClass::V0`** (lines 138-140): directly returns `Ok(RunnableCompiledClass::V0(...))` with **no temporal check at all**.

The developer TODO at lines 136-137 explicitly acknowledges this gap:

```rust
// TODO(shahak): Verify cairo0 as well after get_class_definition_block_number is
// fixed.
```

The non-class-manager fallback path (lines 144-160) uses `get_contract_class`, which calls `get_deprecated_class_definition_at(state_number, class_hash)` — a function that correctly enforces the temporal constraint by checking `state_number.is_before(block_number)`. So the bug is **specific to the class-manager code path**.

**Attack path:**

1. Cairo0 class `X` is declared at block `N` and stored in the class manager via `add_deprecated_class`.
2. Attacker calls `starknet_simulateTransactions` (or `starknet_estimateFee`, `starknet_call`, `starknet_traceTransaction`) specifying `block_id = N-k` (any block before `N`).
3. `ExecutionStateReader` is constructed with `state_number = right_after_block(N-k)` and `class_manager_handle = Some(...)`.
4. During execution, `get_compiled_class(X)` is called.
5. `class_manager_client.get_executable(X)` returns `ContractClass::V0(...)` (the class exists in the manager).
6. The `V0` arm fires — no `is_contract_class_declared` check — and returns `Ok(RunnableCompiledClass::V0(...))`.
7. The simulation proceeds as if `X` was declared at block `N-k`, producing an authoritative-looking wrong result.

Both inputs are fully attacker-controlled via public RPC: the `class_hash` (embedded in the transaction) and the `block_id` (the historical state to simulate at). No operator privileges are required.

---

### Title
Missing temporal declaration check for Cairo0 classes in `get_compiled_class` class-manager path — (`crates/apollo_rpc_execution/src/state_reader.rs`)

### Summary
`ExecutionStateReader::get_compiled_class` enforces `is_contract_class_declared` for `ContractClass::V1` but unconditionally returns `Ok(RunnableCompiledClass::V0(...))` for `ContractClass::V0` when the class manager is active, ignoring `state_number`. An attacker can supply a Cairo0 `class_hash` declared at a later block and a historical `block_id` to make RPC simulation/fee-estimation/tracing treat the class as available at a point in time before it was declared.

### Finding Description
In `get_compiled_class`, when `class_manager_handle` is `Some`, the function queries the class manager for the executable class. For `ContractClass::V1` the result is gated by `is_contract_class_declared` against `self.state_number`. For `ContractClass::V0` there is no such gate — the class is returned unconditionally regardless of when it was declared relative to `state_number`. [1](#0-0) 

The non-class-manager fallback correctly uses `get_deprecated_class_definition_at(state_number, class_hash)`, which enforces the temporal constraint: [2](#0-1) 

The developer TODO at lines 136-137 explicitly acknowledges the missing check: [3](#0-2) 

### Impact Explanation
Any RPC endpoint that accepts a historical `block_id` and internally constructs an `ExecutionStateReader` with `class_manager_handle = Some` — including `starknet_simulateTransactions`, `starknet_estimateFee`, `starknet_call`, and `starknet_traceTransaction` — will return simulation/fee/trace results that incorrectly include Cairo0 classes not yet declared at the queried state. The returned values are authoritative-looking (no error is surfaced) and will mislead callers about historical chain state, contract availability, and fee correctness.

### Likelihood Explanation
The class manager path is the active production path for the sequencer node. Any Cairo0 class declared after block 0 can be used to trigger this. The attacker only needs to observe a Cairo0 class declaration on-chain (public information) and then submit a historical simulation request referencing a block before that declaration. No special privileges are required.

### Recommendation
Apply the same `is_contract_class_declared` guard to the `ContractClass::V0` arm. The storage already supports this via `get_deprecated_class_definition_block_number` / `get_deprecated_class_definition_at`. The TODO comment references a bug in `get_class_definition_block_number` for deprecated classes; that underlying issue should be resolved and the check added:

```rust
ContractClass::V0(deprecated_contract_class) => {
    let is_declared = is_contract_class_declared_v0(
        &self.storage_reader.begin_ro_txn()...,
        &class_hash,
        self.state_number,
    )?;
    if is_declared {
        Ok(RunnableCompiledClass::V0(deprecated_contract_class.try_into()?))
    } else {
        Err(StateError::UndeclaredClassHash(class_hash))
    }
}
```

### Proof of Concept
Build a Rust unit test for `ExecutionStateReader`:

1. Write a Cairo0 class `X` into the class manager (via `add_deprecated_class`).
2. Write storage with `X` declared at `BlockNumber(1)` (not at block 0).
3. Construct `ExecutionStateReader` with `state_number = StateNumber::right_after_block(BlockNumber(0))` and `class_manager_handle = Some(...)`.
4. Call `get_compiled_class(X)`.
5. **Expected**: `Err(StateError::UndeclaredClassHash(X))`.
6. **Actual**: `Ok(RunnableCompiledClass::V0(...))` — the class is returned despite not being declared at `state_number`. [4](#0-3) [5](#0-4)

### Citations

**File:** crates/apollo_rpc_execution/src/state_reader.rs (L115-141)
```rust
        if let Some((class_manager_client, run_time_handle)) = &self.class_manager_handle {
            let contract_class = run_time_handle
                .block_on(class_manager_client.get_executable(class_hash))
                .map_err(|e| StateError::StateReadError(e.to_string()))?
                .ok_or(StateError::UndeclaredClassHash(class_hash))?;

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

**File:** crates/apollo_rpc_execution/src/execution_utils.rs (L64-93)
```rust
pub(crate) fn get_contract_class(
    txn: &StorageTxn<'_, RO>,
    class_hash: &ClassHash,
    state_number: StateNumber,
) -> Result<Option<RunnableCompiledClass>, ExecutionUtilsError> {
    match txn.get_state_reader()?.get_class_definition_block_number(class_hash)? {
        Some(block_number) if state_number.is_before(block_number) => return Ok(None),
        Some(_block_number) => {
            let (Some(casm), Some(sierra)) = txn.get_casm_and_sierra(class_hash)? else {
                return Err(ExecutionUtilsError::CasmTableNotSynced);
            };
            let sierra_version =
                sierra.get_sierra_version().map_err(ExecutionUtilsError::SierraValidationError)?;
            return Ok(Some(RunnableCompiledClass::V1(CompiledClassV1::try_from((
                casm,
                sierra_version,
            ))?)));
        }
        None => {}
    };

    let Some(deprecated_class) =
        txn.get_state_reader()?.get_deprecated_class_definition_at(state_number, class_hash)?
    else {
        return Ok(None);
    };
    Ok(Some(RunnableCompiledClass::V0(
        CompiledClassV0::try_from(deprecated_class).map_err(ExecutionUtilsError::ProgramError)?,
    )))
}
```
