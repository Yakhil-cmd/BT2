[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** storage/storage-interface/src/state_store/state_view/mod.rs (L4-4)
```rust
pub mod cached_state_view;
```

**File:** vm-validator/src/vm_validator.rs (L76-99)
```rust
    fn notify_commit(&mut self) {
        let db_state_view = self.db_state_view();

        // On commit, we need to update the state view so that we can see the latest resources.
        let base_view_id = self.state.state_view_id();
        let new_view_id = db_state_view.id();
        match (base_view_id, new_view_id) {
            (
                StateViewId::TransactionValidation {
                    base_version: old_version,
                },
                StateViewId::TransactionValidation {
                    base_version: new_version,
                },
            ) => {
                // if the state view forms a linear history, just update the state view
                if old_version <= new_version {
                    self.state.reset_state_view(db_state_view.into());
                }
            },
            // if the version is incompatible, we flush the cache
            _ => self.state.reset_all(db_state_view.into()),
        }
    }
```

**File:** vm-validator/src/vm_validator.rs (L146-170)
```rust
    fn validate_transaction(&self, txn: SignedTransaction) -> Result<VMValidatorResult> {
        let vm_validator = self.get_next_vm();

        fail_point!("vm_validator::validate_transaction", |_| {
            Err(anyhow::anyhow!(
                "Injected error in vm_validator::validate_transaction"
            ))
        });

        let result = std::panic::catch_unwind(move || {
            let vm_validator_locked = vm_validator.lock().unwrap();

            use aptos_vm::VMValidator;
            let vm = AptosVM::new(&vm_validator_locked.state.environment);
            vm.validate_transaction(
                txn,
                &vm_validator_locked.state.state_view,
                &vm_validator_locked.state,
            )
        });
        if let Err(err) = &result {
            error!("VMValidator panicked: {:?}", err);
        }
        result.map_err(|_| anyhow::anyhow!("panic validating transaction"))
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L26-47)
```rust
impl DbStateView {
    fn get(&self, key: &StateKey) -> StateViewResult<Option<(Version, StateValue)>> {
        if let Some(version) = self.version {
            if let Some(root_hash) = self.maybe_verify_against_state_root_hash {
                // TODO(aldenhu): sample-verify proof inside DB
                // DB doesn't support returning proofs for buffered state, so only optionally
                // verify proof.
                // TODO: support returning state proof for buffered state.
                if let Ok((value, proof)) =
                    self.db.get_state_value_with_proof_by_version(key, version)
                {
                    proof.verify(root_hash, *key.crypto_hash_ref(), value.as_ref())?;
                }
            }
            Ok(self
                .db
                .get_state_value_with_version_by_version(key, version)?)
        } else {
            Ok(None)
        }
    }
}
```
