No vulnerability found for this question.

**Analysis:** The premise of the exploit is incorrect. The gas-feature-version boundary at `RELEASE_V1_13` only governs *which* limit set (`max_storage_fee_gov` vs `max_storage_fee`) is applied *after* a transaction has already been determined to be an approved governance script — it does not itself determine approval.

Approval is re-derived fresh on every call to `TransactionMetadata::new`, which fetches the *current* `ApprovedExecutionHashes` on-chain config from the resolver and checks whether the script's hash is present in it at that moment: [1](#0-0) 

If the governance entry is removed (e.g., after the proposal is resolved/expired), `ApprovedExecutionHashes::fetch_config` will simply no longer contain that hash, so `is_approved_gov_script` evaluates to `false` on the very next submission — independent of `gas_feature_version`. Since `is_approved_gov_script()` on `TransactionMetadata` is derived from `txn_limits` being `Some(TxnLimitsRequest::ApprovedGovernanceScript)`: [2](#0-1) 

That `txn_limits` field is only set to `ApprovedGovernanceScript` when the fresh lookup succeeds: [3](#0-2) 

With `txn_limits` being `None` after removal, `check_gas` in `aptos-move/aptos-vm/src/gas.rs` will not take the `is_approved_gov_script()` branch, so `max_transaction_size_in_bytes_gov` is not applied: [4](#0-3) 

And `StandardGasAlgebra::new` will not select `max_storage_fee_gov`, `max_execution_gas_gov`, or `max_io_gas_gov` either, since `txn_limits_request` won't be `Some(TxnLimitsRequest::ApprovedGovernanceScript)`: [5](#0-4) 

So the proposed proof-of-concept scenario (seed `ApprovedExecutionHashes`, remove the entry, resubmit the stale-hash transaction at the `RELEASE_V1_13` boundary) actually behaves correctly: the removal takes effect immediately because approval is checked live against current on-chain state on every transaction, not cached or bound to a stale proposal ID. There is no window where the `gas_feature_version` boundary alone can cause a removed/stale approval to still receive governance storage-fee limits — the approval check and the gas-feature-version check are independent gates, and both must hold. This does not meet the bar of an unprivileged input corrupting sender/signer/replay/domain-binding guarantees at the admission boundary.

### Citations

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L67-82)
```rust
        let (script_hash, is_approved_gov_script) =
            if let Ok(TransactionExecutableRef::Script(s)) = txn.payload().executable_ref() {
                let script_hash = HashValue::sha3_256_of(s.code()).to_vec();
                let is_approved_gov_script = ApprovedExecutionHashes::fetch_config(resolver)
                    .ok()
                    .flatten()
                    .is_some_and(|approved| {
                        approved
                            .entries
                            .iter()
                            .any(|(_, hash)| hash == &script_hash)
                    });
                (script_hash, is_approved_gov_script)
            } else {
                (vec![], false)
            };
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L93-103)
```rust
        let txn_limits = if is_approved_gov_script {
            if txn_limits_request.is_some() {
                return Err(VMStatus::error(
                    StatusCode::TXN_LIMITS_REQUEST_NOT_ALLOWED_FOR_GOVERNANCE_SCRIPT,
                    Some(
                        "Higher transaction limits cannot be requested for governance proposals"
                            .to_string(),
                    ),
                ));
            }
            Some(TxnLimitsRequest::ApprovedGovernanceScript)
```

**File:** aptos-move/aptos-vm/src/transaction_metadata.rs (L345-350)
```rust
    /// Returns true if this is a governance proposal script that was approved.
    pub fn is_approved_gov_script(&self) -> bool {
        self.txn_limits
            .as_ref()
            .is_some_and(|r| matches!(r, TxnLimitsRequest::ApprovedGovernanceScript))
    }
```

**File:** aptos-move/aptos-vm/src/gas.rs (L84-97)
```rust
    if txn_metadata.is_approved_gov_script() {
        let max_txn_size_gov = if gas_feature_version >= RELEASE_V1_13 {
            gas_params.vm.txn.max_transaction_size_in_bytes_gov
        } else {
            MAXIMUM_APPROVED_TRANSACTION_SIZE_LEGACY.into()
        };

        if txn_bytes_len > max_txn_size_gov
            // Ensure that it is only the approved payload that exceeds the
            // maximum. The (unknown) user input should be restricted to the original
            // maximum transaction size.
            || txn_bytes_len
                > txn_metadata.script_size + txn_gas_params.max_transaction_size_in_bytes
        {
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L74-107)
```rust
        let (max_execution_gas, max_io_gas, max_storage_fee) = match txn_limits_request {
            Some(TxnLimitsRequest::ApprovedGovernanceScript)
                if gas_feature_version >= gas_feature_versions::RELEASE_V1_13 =>
            {
                (
                    vm_gas_params.txn.max_execution_gas_gov,
                    vm_gas_params.txn.max_io_gas_gov,
                    vm_gas_params.txn.max_storage_fee_gov,
                )
            },
            Some(TxnLimitsRequest::Staking(request)) => {
                // Multipliers are expressed as percent of the base limit
                // (100 = 1x).
                let m = request.multipliers();
                let max_execution_gas = u64::from(vm_gas_params.txn.max_execution_gas)
                    .saturating_mul(m.execution_multiplier_percent())
                    / 100;
                let max_io_gas = u64::from(vm_gas_params.txn.max_io_gas)
                    .saturating_mul(m.io_multiplier_percent())
                    / 100;

                (
                    InternalGas::new(max_execution_gas),
                    InternalGas::new(max_io_gas),
                    // Storage limits are kept as is.
                    vm_gas_params.txn.max_storage_fee,
                )
            },
            // Pre v1.13 governance scripts or no request: use standard limits.
            None | Some(TxnLimitsRequest::ApprovedGovernanceScript) => (
                vm_gas_params.txn.max_execution_gas,
                vm_gas_params.txn.max_io_gas,
                vm_gas_params.txn.max_storage_fee,
            ),
```
