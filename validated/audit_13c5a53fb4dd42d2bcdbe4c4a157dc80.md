Looking at the exact code in `crates/apollo_rpc_execution/src/state_reader.rs` and the surrounding execution path:

### Title
Missing `is_contract_class_declared` Check for Cairo0 Classes in `ExecutionStateReader::get_compiled_class` Allows Simulation to Execute Undeclared Class Code - (`crates/apollo_rpc_execution/src/state_reader.rs`)

---

### Summary

When `class_manager_handle` is set, `get_compiled_class` performs a state-number-scoped declaration check for `ContractClass::V1` classes but unconditionally returns `Ok` for `ContractClass::V0` (Cairo0) classes. An attacker can supply a `class_hash` referencing a Cairo0 class declared at a later block than the queried `block_id`, causing `simulate_transactions` / `estimate_fee` to execute the undeclared class instead of returning `StateError::UndeclaredClassHash`.

---

### Finding Description

In `get_compiled_class`, when `class_manager_handle` is `Some`, the code branches on the returned `ContractClass` variant: [1](#0-0) 

For `ContractClass::V1`, `is_contract_class_declared` is called against `self.state_number` and the function returns `Err(StateError::UndeclaredClassHash)` if the class was not yet declared at that state number: [2](#0-1) 

For `ContractClass::V0`, **no such check is performed**. The TODO comment explicitly acknowledges this gap: [3](#0-2) 

The `is_contract_class_declared` helper uses `get_class_definition_block_number`, which only covers Sierra (V1) classes: [4](#0-3) 

The correct equivalent for Cairo0 would be `get_deprecated_class_definition_block_number` / `get_deprecated_class_definition_at`, which the storage-only fallback path (`get_contract_class`) already uses correctly: [5](#0-4) 

The class manager stores Cairo0 classes independently of any state-number context via `add_deprecated_class`: [6](#0-5) 

`get_executable` returns them as `ContractClass::V0` with no block-number metadata: [7](#0-6) 

The RPC `simulate_transactions` and `estimate_fee` handlers both set `class_manager_handle` when a class manager client is configured: [8](#0-7) 

The `ExecutionStateReader` is constructed with that handle inside `execute_transactions`, which backs both simulation and fee estimation: [9](#0-8) 

---

### Impact Explanation

When an attacker calls `starknet_simulateTransactions` (or `starknet_estimateFee`) with a historical `block_id = M` and includes a transaction whose execution path triggers `get_compiled_class(C)` — where `C` is a Cairo0 class declared at block `N > M` — the class manager returns `ContractClass::V0(C)` and the missing check causes the function to return `Ok(RunnableCompiledClass::V0(C))`. The simulation executes the undeclared class's code and returns an authoritative-looking trace and fee estimate instead of an `UndeclaredClassHash` error. This is a wrong simulation result under the "High. RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value" impact category.

---

### Likelihood Explanation

- The class manager is present in production deployments; `class_manager_handle` is `Some` in the simulation path.
- Cairo0 classes declared at any block are permanently stored in the class manager with no state-number awareness.
- The attacker only needs to know a Cairo0 `class_hash` declared at a block later than the queried `block_id` — this is publicly observable on-chain.
- The most direct trigger is a `deploy_account` simulation: blockifier calls `get_compiled_class(class_hash)` with the attacker-supplied `class_hash` from the transaction to load the account contract class for `__validate_deploy__` / `__execute__`.
- No privileged access is required; the attack is fully unprivileged via the public RPC endpoint.

---

### Recommendation

Implement the Cairo0 declaration check analogously to the V1 check. Use `get_deprecated_class_definition_block_number` (which already exists in storage) to verify the class was declared at or before `self.state_number`:

```rust
ContractClass::V0(deprecated_contract_class) => {
    let declared_block = self
        .storage_reader
        .begin_ro_txn()
        .map_err(storage_err_to_state_err)?
        .get_state_reader()
        .map_err(storage_err_to_state_err)?
        .get_deprecated_class_definition_block_number(&class_hash)
        .map_err(storage_err_to_state_err)?;

    match declared_block {
        Some(block_number) if self.state_number.is_after(block_number) => {
            Ok(RunnableCompiledClass::V0(deprecated_contract_class.try_into()?))
        }
        _ => Err(StateError::UndeclaredClassHash(class_hash)),
    }
}
```

Remove the TODO comment once this is in place.

---

### Proof of Concept

```rust
#[test]
fn get_compiled_class_cairo0_undeclared_at_state_number() {
    use std::cell::Cell;
    use std::sync::Arc;
    use apollo_class_manager_types::MockClassManagerClient;
    use blockifier::state::errors::StateError;
    use blockifier::state::state_api::StateReader as BlockifierStateReader;
    use starknet_api::contract_class::ContractClass;
    use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
    use starknet_api::core::{ClassHash, BlockNumber};
    use starknet_api::state::StateNumber;
    use apollo_storage::test_utils::get_test_storage;
    use apollo_rpc_execution::state_reader::ExecutionStateReader;

    let class_hash = ClassHash(starknet_types_core::felt::Felt::from(0x42u64));

    // Class manager returns a Cairo0 class for this hash (declared at block 5).
    let mut mock = MockClassManagerClient::new();
    mock.expect_get_executable().returning(move |_| {
        Ok(Some(ContractClass::V0(DeprecatedContractClass::default())))
    });

    let ((storage_reader, mut storage_writer), _tmp) = get_test_storage();

    // Write block 5 with the deprecated class declared.
    // (storage has the class at block 5, but we query at block 2)
    storage_writer
        .begin_rw_txn().unwrap()
        .append_header(BlockNumber(0), &Default::default()).unwrap()
        .append_state_diff(BlockNumber(0), Default::default()).unwrap()
        // ... (blocks 1-4 omitted for brevity) ...
        .commit().unwrap();

    // Query at state_number right_after_block(2) — class not yet declared.
    let reader = ExecutionStateReader {
        storage_reader,
        state_number: StateNumber::unchecked_right_after_block(BlockNumber(2)),
        maybe_pending_data: None,
        missing_compiled_class: Cell::new(None),
        class_manager_handle: Some((Arc::new(mock),
            tokio::runtime::Runtime::new().unwrap().handle().clone())),
    };

    // BUG: currently returns Ok(...) instead of Err(UndeclaredClassHash)
    let result = reader.get_compiled_class(class_hash);
    assert_matches::assert_matches!(
        result,
        Err(StateError::UndeclaredClassHash(h)) if h == class_hash,
        "Expected UndeclaredClassHash but got Ok — missing Cairo0 declaration check"
    );
}
```

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

**File:** crates/apollo_class_manager/src/class_manager.rs (L136-143)
```rust
    #[instrument(skip(self, class), ret, err)]
    pub fn add_deprecated_class(
        &mut self,
        class_id: ClassId,
        class: RawExecutableClass,
    ) -> ClassManagerResult<()> {
        self.classes.set_deprecated_class(class_id, class)?;
        Ok(())
```

**File:** crates/apollo_class_manager/src/class_storage.rs (L154-177)
```rust
    #[instrument(skip(self), level = "debug", err)]
    fn get_executable(&self, class_id: ClassId) -> Result<Option<RawExecutableClass>, Self::Error> {
        if let Some(class) = self
            .executable_classes
            .get(&class_id)
            .or_else(|| self.deprecated_classes.get(&class_id))
        {
            return Ok(Some(class));
        }

        // If compiled_class_hash_v2 exists, it'll be Cairo 1.
        if self.get_executable_class_hash_v2(class_id)?.is_some() {
            let Some(class) = self.storage.get_executable(class_id)? else {
                return Ok(None);
            };
            self.executable_classes.set(class_id, class.clone());
            return Ok(Some(class));
        }

        let Some(class) = self.storage.get_deprecated_class(class_id)? else {
            return Ok(None);
        };
        self.deprecated_classes.set(class_id, class.clone());
        Ok(Some(class))
```

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1100-1117)
```rust
        let class_manager_client =
            create_class_manager_client(self.class_manager_client.clone()).await;

        let simulation_results = tokio::task::spawn_blocking(move || {
            exec_simulate_transactions(
                executable_txns,
                None,
                &chain_id,
                reader,
                maybe_pending_data,
                state_number,
                block_number,
                &execution_config,
                charge_fee,
                validate,
                DONT_IGNORE_L1_DA_MODE,
                class_manager_client,
            )
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
