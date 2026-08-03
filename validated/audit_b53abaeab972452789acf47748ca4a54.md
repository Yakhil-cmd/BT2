[1](#0-0) [2](#0-1)

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3539-3557)
```rust
        let mut gas_meter = make_prod_gas_meter(
            self.gas_feature_version(),
            vm_params,
            storage_gas_params,
            txn_data.txn_limits.as_ref(),
            initial_balance,
            &NoopBlockSynchronizationKillSwitch {},
        );
        let storage = TraversalStorage::new();

        // Increment the counter for transactions verified.
        let (counter_label, result) = match self.validate_signed_transaction(
            &mut session,
            module_storage,
            &txn,
            &txn_data,
            &log_context,
            &mut TraversalContext::new(&storage),
            &mut gas_meter,
```

**File:** aptos-move/aptos-vm/src/gas.rs (L181-199)
```rust
    let intrinsic_gas = txn_gas_params
        .calculate_intrinsic_gas(txn_bytes_len)
        .evaluate(gas_feature_version, &gas_params.vm);
    let total_rounded: Gas = (intrinsic_gas + keyless + slh_dsa_sha2_128s + encrypted_txn_cost)
        .to_unit_round_up_with_params(txn_gas_params);
    if txn_metadata.max_gas_amount() < total_rounded {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; min {}, submitted {}",
                total_rounded,
                txn_metadata.max_gas_amount()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::MAX_GAS_UNITS_BELOW_MIN_TRANSACTION_GAS_UNITS,
            None,
        ));
    }
```
