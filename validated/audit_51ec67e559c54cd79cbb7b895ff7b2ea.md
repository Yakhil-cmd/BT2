No vulnerability found for this question.

**Rationale:**

The scenario assumes that a stale, cached account state in the mempool-side `vm-validator` could let a transaction signed with a pre-rotation authentication key be admitted and *executed* after a key rotation. This doesn't hold up:

- `vm-validator`'s `VMValidator` does keep a `CachedModuleView`/`CachedDbStateView` for speculative pre-execution admission checks, refreshed via `notify_commit`/`restart` [1](#0-0) . However, this cache only affects whether a transaction is *speculatively* accepted into mempool — it is not the authoritative execution path.
- The binding authoritative check happens in `prologue_common` inside `transaction_validation.move`, which is run for every transaction as part of actual block execution against the live ledger state at that point, not any client-side cache. It calls `account::get_authentication_key(sender_address)` and asserts the transaction's `txn_authentication_key` matches it, aborting with `PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY` otherwise [2](#0-1) .
- `AptosVM::validate_transaction` (the `VMValidator` trait impl used by `vm-validator`) itself re-verifies the signature and re-runs the prologue session against the `state_view` passed in for that specific check, and any actual block execution independently reruns this prologue against the committed ledger state at execution time [3](#0-2) .

So even if a stale mempool-side cache momentarily admits a transaction signed against a pre-rotation key, the actual state transition/commit is gated by the on-chain `account::get_authentication_key` check executed fresh at block-execution time, which reflects the post-rotation key. A transaction signed with the old key would be rejected with `PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY` at that point and never commit, so `set_stake_pool_operator` (`staking_proxy.move` line 51) could never execute under the wrong signer's authority via this path [4](#0-3) .

Additionally, `set_stake_pool_operator`'s actual authorization is based on the `OwnerCapability` resource existing at the signer's address (checked via `stake::set_operator`/`assert_owner_cap_exists`), which is a separate account-scoped resource independent from the authentication key itself [5](#0-4) . Key rotation does not change the address or move the `OwnerCapability`, so there's no "owner_capability post-rotation" address mismatch as hypothesized.

This confirms the decision standard's rejection criterion: mempool/vm-validator caching and VM prologue checks converge correctly on the current on-chain auth key at execution/commit time, so the described admission bypass is not realizable.

### Citations

**File:** vm-validator/src/vm_validator.rs (L42-99)
```rust
struct VMValidator {
    db_reader: Arc<dyn DbReader>,
    state: CachedModuleView<CachedDbStateView>,
}

impl Clone for VMValidator {
    fn clone(&self) -> Self {
        Self::new(self.db_reader.clone())
    }
}

impl VMValidator {
    fn new(db_reader: Arc<dyn DbReader>) -> Self {
        let db_state_view = db_reader
            .latest_state_checkpoint_view()
            .expect("Get db view cannot fail");
        VMValidator {
            db_reader,
            state: CachedModuleView::new(db_state_view.into()),
        }
    }

    fn db_state_view(&self) -> DbStateView {
        self.db_reader
            .latest_state_checkpoint_view()
            .expect("Get db view cannot fail")
    }

    fn restart(&mut self) -> Result<()> {
        let db_state_view = self.db_state_view();
        self.state.reset_all(db_state_view.into());
        Ok(())
    }

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

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L143-166)
```text
        // Check if the authentication key is valid
        if (!skip_auth_key_check(is_simulation, &txn_authentication_key)) {
            if (txn_authentication_key.is_some()) {
                let authentication_key = if (
                    sender_address != gas_payer_address &&
                        !account::exists_at(sender_address) &&
                        features::sponsored_automatic_account_creation_enabled()
                ) {
                    // This is a sponsored transaction with account that does
                    // not exist and there is no default account resource.
                    bcs::to_bytes(&sender_address)
                } else {
                    account::get_authentication_key(sender_address)
                };
                assert!(
                    txn_authentication_key.destroy_some() == authentication_key,
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                );
            } else {
                assert!(
                    allow_missing_txn_authentication_key(sender_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                );
            };
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3524-3541)
```rust
        let Ok(txn) = transaction.check_signature() else {
            return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
        };
        let auxiliary_info = AuxiliaryInfo::new_timestamp_not_yet_assigned(0);
        let resolver = self.as_move_resolver(&state_view);
        let txn_data = match TransactionMetadata::new(self, &resolver, &txn, &auxiliary_info) {
            Ok(data) => data,
            Err(err) => {
                return VMValidatorResult::new(Some(err.status_code()), 0);
            },
        };

        let mut session = self.new_session(
            &resolver,
            SessionId::prologue_meta(&txn_data),
            Some(txn_data.as_user_transaction_context()),
        );

```

**File:** aptos-move/framework/aptos-framework/sources/staking_proxy.move (L51-56)
```text
    public entry fun set_stake_pool_operator(owner: &signer, new_operator: address) {
        let owner_address = signer::address_of(owner);
        if (stake::stake_pool_exists(owner_address)) {
            stake::set_operator(owner, new_operator);
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L834-841)
```text
    public entry fun set_operator(
        owner: &signer, new_operator: address
    ) acquires OwnerCapability, StakePool {
        let owner_address = signer::address_of(owner);
        assert_owner_cap_exists(owner_address);
        let ownership_cap = borrow_global<OwnerCapability>(owner_address);
        set_operator_with_cap(ownership_cap, new_operator);
    }
```
