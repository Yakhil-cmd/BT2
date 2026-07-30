[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** crates/sui-types/src/execution_params.rs (L15-18)
```rust
/// Execution inputs computed before running a transaction: whether to fail it early (and with
/// which errors), plus context for gas charging. An execution input only - never serialized into
/// `TransactionEffects`, so adding fields here does not change effects or their digests.
#[derive(Debug, Clone)]
```

**File:** crates/sui-types/src/execution_params.rs (L19-25)
```rust
pub struct ExecutionOrEarlyError {
    early_errors: Option<NonEmpty<ExecutionErrorKind>>,
    /// Accumulator (settlement) root version assigned to this transaction. Gates the mainnet
    /// address-balance gas-smash short-circuit. Populated only for mainnet committed execution;
    /// `None` elsewhere, leaving that gate inert.
    accumulator_version: Option<SequenceNumber>,
}
```

**File:** sui-execution/latest/sui-adapter/src/execution_engine.rs (L339-358)
```rust
        pub(super) fn should_filter_address_balance_gas_smash(
            execution_params: &ExecutionOrEarlyError,
            protocol_config: &ProtocolConfig,
        ) -> bool {
            if !head_error_is_insufficient_funds_for_withdraw(execution_params) {
                return false;
            }
            debug_assert!(
                !protocol_config.early_exit_on_iffw(),
                "Should not reach gas smashing filtering address balances if IFFW early exit is enabled"
            );
            // In test/debug builds, always apply the fix unconditionally to match the behaviour of
            // the 1.72 mainnet release (where it was deployed as an ungated hotfix).
            in_test_configuration()
                || protocol_config.early_exit_on_iffw()
                || (protocol_config.chain() == Chain::Mainnet
                    && execution_params
                        .accumulator_version()
                        .is_some_and(|v| v >= ADDRESS_BALANCE_SMASH_FIX_MIN_ACCUMULATOR_VERSION))
        }
```

**File:** sui-execution/latest/sui-adapter/src/execution_engine.rs (L360-389)
```rust
        /// Whether to short-circuit an IFFW transaction. When an accumulator version is assigned
        /// (mainnet committed execution) it gates on the settlement-version rollout point; otherwise
        /// (every other chain and non-committed paths, where no accumulator version is assigned) the
        /// short-circuit applies based on `early_exit_on_iffw`.
        pub(super) fn should_short_circuit_insufficient_funds(
            execution_params: &ExecutionOrEarlyError,
            protocol_config: &ProtocolConfig,
        ) -> bool {
            // If no IFWWs, then does not apply
            if !execution_params.early_errors().is_some_and(|errors| {
                errors
                    .iter()
                    .any(|e| matches!(e, ExecutionErrorKind::InsufficientFundsForWithdraw))
            }) {
                return false;
            }

            // In test/debug builds, always short-circuit unconditionally to match the behaviour of
            // the 1.72 mainnet release (where it was deployed as an ungated hotfix).
            if in_test_configuration() {
                return true;
            }

            // otherwise gate by accumulator version (if present) or protocol flag
            protocol_config.early_exit_on_iffw()
                || (protocol_config.chain() == Chain::Mainnet
                    && execution_params.accumulator_version().is_some_and(|v| {
                        v >= ADDRESS_BALANCE_SMASH_SHORT_CIRCUIT_MIN_ACCUMULATOR_VERSION
                    }))
        }
```

**File:** sui-execution/latest/sui-adapter/src/execution_engine.rs (L1943-1968)
```rust
        #[test]
        fn inert_without_accumulator_version() {
            // Non-IFFW early errors never filter, regardless of test configuration.
            let above = version(ADDRESS_BALANCE_SMASH_FIX_MIN_ACCUMULATOR_VERSION.value() + 1);
            assert!(!should_filter_address_balance_gas_smash(
                &ExecutionOrEarlyError::ok(above),
                &config_without_flag(),
            ));
            assert!(!should_filter_address_balance_gas_smash(
                &ExecutionOrEarlyError::failed(
                    NonEmpty::new(ExecutionErrorKind::CertificateDenied),
                    above
                ),
                &config_without_flag(),
            ));
            // In test/debug builds, IFFW with no accumulator version returns true (matches
            // the ungated 1.72 mainnet hotfix). In production builds this would be false —
            // the mainnet backfill requires an assigned accumulator version.
            assert!(should_filter_address_balance_gas_smash(
                &ExecutionOrEarlyError::failed(
                    NonEmpty::new(ExecutionErrorKind::InsufficientFundsForWithdraw),
                    None,
                ),
                &config_without_flag(),
            ));
        }
```

**File:** sui-execution/latest/sui-adapter/src/execution_engine.rs (L2060-2080)
```rust
        #[test]
        fn no_accumulator_version_short_circuits_in_test_configuration() {
            // In test/debug builds, IFFW with no accumulator version always short-circuits
            // (matches the ungated 1.72 mainnet hotfix, preventing fork scenarios in tests).
            // In production builds without the flag, this would return false — the mainnet
            // compiled-constant backfill requires an assigned accumulator version.
            assert!(should_short_circuit_insufficient_funds(
                &iffw(None),
                &config_without_flag(),
            ));
        }

        #[test]
        fn no_accumulator_version_short_circuits_with_protocol_flag() {
            // Once the protocol flag is active, chains without accumulator versions should use the
            // new short-circuit behavior.
            assert!(should_short_circuit_insufficient_funds(
                &iffw(None),
                &config_with_flag(),
            ));
        }
```
