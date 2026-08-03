[1](#0-0) [2](#0-1) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L425-427)
```rust
    /// Rejects authenticator/signature variants whose feature flag is not yet
    /// enabled. Called from both mempool validation and the execution paths.
    fn check_authenticator_features(
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L655-691)
```rust
        let txn_status = TransactionStatus::from_vm_status(
            error_vm_status.clone(),
            self.features(),
            self.gas_feature_version() >= RELEASE_V1_38,
        );

        match txn_status {
            TransactionStatus::Keep(status) => {
                // The transaction should be kept. Run the appropriate post transaction workflows
                // including epilogue. This runs a new session that ignores any side effects that
                // might abort the execution (e.g., spending additional funds needed to pay for
                // gas). Even if the previous failure occurred while running the epilogue, it
                // should not fail now. If it somehow fails here, there is no choice but to
                // discard the transaction.
                let output = self
                    .finish_aborted_transaction(
                        prologue_session_change_set,
                        gas_meter,
                        txn_data,
                        resolver,
                        module_storage,
                        serialized_signers,
                        status,
                        log_context,
                        change_set_configs,
                        traversal_context,
                    )
                    .unwrap_or_else(|status| discarded_output(status.status_code()));
                (error_vm_status, output)
            },
            TransactionStatus::Discard(status_code) => {
                let discarded_output = discarded_output(status_code);
                (error_vm_status, discarded_output)
            },
            TransactionStatus::Retry => unreachable!(),
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2153-2166)
```rust
        // Revalidate the transaction.
        let mut prologue_session = PrologueSession::new(self, &txn_data, resolver);
        let initial_gas = gas_meter.balance();
        let serialized_signers = unwrap_or_discard!(prologue_session.execute(|session| {
            self.validate_signed_transaction(
                session,
                code_storage,
                txn,
                &txn_data,
                log_context,
                &mut traversal_context,
                gas_meter,
            )
        }));
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3499-3501)
```rust
        if let Err(err) = self.check_authenticator_features(transaction.authenticator_ref()) {
            return VMValidatorResult::error(err.status_code());
        }
```

**File:** types/src/transaction/mod.rs (L1891-1919)
```rust
    pub fn from_vm_status(
        vm_status: VMStatus,
        features: &Features,
        memory_limit_exceeded_as_miscellaneous_error: bool,
    ) -> Self {
        let status_code = vm_status.status_code();
        // TODO: keep_or_discard logic should be deprecated from Move repo and refactored into here.
        match vm_status.keep_or_discard(
            features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES),
            memory_limit_exceeded_as_miscellaneous_error,
            features.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V10),
        ) {
            Ok(recorded) => match recorded {
                // TODO(bowu):status code should be removed from transaction status
                KeptVMStatus::MiscellaneousError => {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(status_code)))
                },
                _ => Self::Keep(recorded.into()),
            },
            Err(code) => {
                if code.status_type() == StatusType::InvariantViolation
                    && features.is_enabled(FeatureFlag::CHARGE_INVARIANT_VIOLATION)
                {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(code)))
                } else {
                    Self::Discard(code)
                }
            },
        }
```

**File:** aptos-move/e2e-testsuite/src/tests/verify_txn.rs (L205-209)
```rust
    assert_prologue_parity!(
        executor.validate_transaction(signed_txn.clone()).status(),
        executor.execute_transaction(signed_txn).status(),
        StatusCode::INVALID_AUTH_KEY
    );
```

**File:** aptos-move/e2e-testsuite/src/tests/verify_txn.rs (L254-258)
```rust
    assert_prologue_parity!(
        executor.validate_transaction(txn.clone()).status(),
        executor.execute_transaction(txn).status(),
        StatusCode::INVALID_AUTH_KEY
    );
```
