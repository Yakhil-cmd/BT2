### Title
`estimate_minimal_gas_vector` omits `n_compiled_class_hash_updates` for Declare transactions, underestimating DA gas and allowing under-priced admission - (File: `crates/blockifier/src/fee/gas_usage.rs`)

### Summary

`estimate_minimal_gas_vector` hard-codes `n_compiled_class_hash_updates: 0` for `Transaction::Declare`, despite a developer TODO acknowledging it should be 1. Every Declare transaction writes a `(class_hash, compiled_class_hash)` pair to the on-chain DA segment (2 felts), but this cost is invisible to the minimum-fee check. The blockifier's `check_fee_bounds` — called during both gateway stateful validation and block execution — therefore accepts Declare transactions whose resource bounds are below the true minimum, letting users underpay and leaving the sequencer undercompensated for the DA cost.

### Finding Description

In `crates/blockifier/src/fee/gas_usage.rs`, `estimate_minimal_gas_vector` builds a `StateChangesCount` for each transaction type and uses it to compute the minimum DA gas cost:

```rust
// lines 168-174
Transaction::Declare(_) => StateChangesCount {
    n_storage_updates: 1,
    n_class_hash_updates: 0,
    // TODO(Yoni): BLOCKIFIER-RESET: should be 1.
    n_compiled_class_hash_updates: 0,
    n_modified_contracts: 1,
},
``` [1](#0-0) 

The developer TODO explicitly states the correct value is 1. `get_onchain_data_segment_length` adds `n_compiled_class_hash_updates * 2` felts to the DA segment:

```rust
// line 34
onchain_data_segment_length += state_changes_count.n_compiled_class_hash_updates * 2;
``` [2](#0-1) 

With `n_compiled_class_hash_updates: 0`, `get_da_gas_cost` omits the cost of those 2 felts entirely. The resulting `GasVector` is then used in `check_fee_bounds` inside `perform_pre_validation_stage`:

```rust
// lines 374-382
fn check_fee_bounds(&self, tx_context: &TransactionContext) -> ... {
    let minimal_gas_amount_vector = estimate_minimal_gas_vector(
        &tx_context.block_context,
        self,
        &tx_context.get_gas_vector_computation_mode(),
    );
    ...
    // checks user's resource_bounds >= minimal_gas_amount_vector
``` [3](#0-2) [4](#0-3) 

Because the minimum is underestimated, a user can set `l1_data_gas.max_amount` (KZG DA mode) or `l1_gas.max_amount` (calldata DA mode) exactly at the underestimated minimum and pass `check_fee_bounds`. The actual execution then charges the true DA cost, which exceeds the user's resource bounds, triggering a post-execution overdraft.

**Magnitude of the missing cost:**
- **KZG DA mode**: `2 × DATA_GAS_PER_FIELD_ELEMENT = 2 × 32 = 64` blob gas units per Declare transaction.
- **Calldata DA mode**: `2 × SHARP_GAS_PER_DA_WORD = 2 × 551 = 1102` L1 gas units per Declare transaction. [5](#0-4) 

### Impact Explanation

When a user submits a Declare transaction with resource bounds set to the (underestimated) minimum:

1. `check_fee_bounds` passes — the underestimated minimum is ≤ the user's bounds.
2. `verify_can_pay_committed_bounds` passes — the user has enough balance to cover their (too-low) bounds.
3. Execution proceeds; the actual DA gas for the compiled class hash is charged.
4. `PostExecutionReport::new` detects `actual_gas > resource_bounds` → `MaxGasAmountExceeded`.
5. For non-revertible Declare transactions, this surfaces as a hard error; the recommended fee charged is `min(actual_gas, resource_bounds) × price` — i.e., the user pays only up to their (too-low) bound.
6. The sequencer absorbs the difference between the true DA cost and what the user paid.

This is a **Critical** impact: incorrect fee/gas accounting with direct economic impact on the sequencer, and a **High** impact: the gateway stateful path (which runs blockifier validation) admits Declare transactions that should be rejected for insufficient resource bounds. [6](#0-5) [7](#0-6) 

### Likelihood Explanation

Any unprivileged user can submit a Declare transaction. The only requirement is to set `l1_data_gas.max_amount` (or `l1_gas.max_amount` in calldata mode) to the value returned by `estimate_minimal_gas_vector`, which is publicly computable. No special knowledge or privileged access is needed. The bug is triggered on every Declare transaction whose resource bounds are set at the underestimated minimum.

### Recommendation

Change `n_compiled_class_hash_updates` from `0` to `1` for `Transaction::Declare` in `estimate_minimal_gas_vector`, as the TODO comment already acknowledges:

```rust
Transaction::Declare(_) => StateChangesCount {
    n_storage_updates: 1,
    n_class_hash_updates: 0,
    n_compiled_class_hash_updates: 1,  // was 0; Declare writes (class_hash, compiled_class_hash)
    n_modified_contracts: 1,
},
``` [1](#0-0) 

### Proof of Concept

1. Compute `min_gas = estimate_minimal_gas_vector(block_context, declare_tx, AllResources)`. This returns a `GasVector` with `l1_data_gas = 0` (KZG DA mode) because `n_compiled_class_hash_updates = 0`.
2. Submit a Declare V3 transaction with `AllResourceBounds { l1_data_gas: { max_amount: 0, ... }, ... }`.
3. `check_fee_bounds` passes: `0 >= 0` (underestimated minimum).
4. `verify_can_pay_committed_bounds` passes: user balance covers the (zero) l1_data_gas bound.
5. Execution charges the true DA cost: `2 × DATA_GAS_PER_FIELD_ELEMENT = 64` blob gas.
6. `PostExecutionReport` detects `64 > 0` → `MaxGasAmountExceeded { resource: L1DataGas, max_amount: 0, actual_amount: 64 }`.
7. Recommended fee = `min(64, 0) × l1_data_gas_price = 0` — user pays nothing for DA; sequencer bears the cost. [3](#0-2) [8](#0-7)

### Citations

**File:** crates/blockifier/src/fee/gas_usage.rs (L33-35)
```rust
    // For each compiled class updated (through declare): class_hash, compiled_class_hash
    onchain_data_segment_length += state_changes_count.n_compiled_class_hash_updates * 2;

```

**File:** crates/blockifier/src/fee/gas_usage.rs (L156-214)
```rust
/// Returns an estimated lower bound for the gas required by the given account transaction.
pub fn estimate_minimal_gas_vector(
    block_context: &BlockContext,
    tx: &AccountTransaction,
    gas_usage_vector_computation_mode: &GasVectorComputationMode,
) -> GasVector {
    // TODO(Dori, 1/8/2023): Give names to the constant VM step estimates and regression-test them.
    let BlockContext { block_info, versioned_constants, .. } = block_context;
    let state_changes_by_account_tx = match &tx.tx {
        // We consider the following state changes: sender balance update (storage update) + nonce
        // increment (contract modification) (we exclude the sequencer balance update and the ERC20
        // contract modification since it occurs for every tx).
        Transaction::Declare(_) => StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            // TODO(Yoni): BLOCKIFIER-RESET: should be 1.
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        },
        Transaction::Invoke(_) => StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        },
        // DeployAccount also updates the address -> class hash mapping.
        Transaction::DeployAccount(_) => StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 1,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        },
    };

    // TODO(Yoni): BLOCKIFIER-RESET: reuse TransactionReceipt code.
    let data_segment_length = get_onchain_data_segment_length(&state_changes_by_account_tx);
    let os_steps_for_type = versioned_constants
        .os_resources_for_tx_type(&tx.tx_type(), tx.extended_calldata_length())
        .n_steps
        + versioned_constants.os_kzg_da_resources(data_segment_length).n_steps;

    let resources = ExtendedExecutionResources {
        vm_resources: ExecutionResources { n_steps: os_steps_for_type, ..Default::default() },
        ..Default::default()
    };
    let da_gas_cost = get_da_gas_cost(&state_changes_by_account_tx, block_info.use_kzg_da);
    let vm_resources_cost = get_extended_vm_resources_cost(
        versioned_constants,
        &resources,
        0,
        gas_usage_vector_computation_mode,
    );
    da_gas_cost.checked_add(vm_resources_cost).unwrap_or_else(|| {
        panic!(
            "Overflow in minimal gas estimation; attempted to add {da_gas_cost:?} to \
             {vm_resources_cost:?}"
        )
    })
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-382)
```rust
    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let minimal_gas_amount_vector = estimate_minimal_gas_vector(
            &tx_context.block_context,
            self,
            &tx_context.get_gas_vector_computation_mode(),
        );
```

**File:** crates/blockifier/src/fee/eth_gas_constants.rs (L8-31)
```rust
pub const FIELD_ELEMENTS_PER_BLOB: usize = 1 << 12;
pub const DATA_GAS_PER_BLOB: usize = 1 << 17;
pub const DATA_GAS_PER_FIELD_ELEMENT: usize = DATA_GAS_PER_BLOB / FIELD_ELEMENTS_PER_BLOB;

// Storage.
pub const GAS_PER_ZERO_TO_NONZERO_STORAGE_SET: usize = 20000;
pub const GAS_PER_COLD_STORAGE_ACCESS: usize = 2100;
pub const GAS_PER_NONZERO_TO_INT_STORAGE_SET: usize = 2900;
pub const GAS_PER_COUNTER_DECREASE: usize =
    GAS_PER_COLD_STORAGE_ACCESS + GAS_PER_NONZERO_TO_INT_STORAGE_SET;

// Events.
pub const GAS_PER_LOG: usize = 375;
pub const GAS_PER_LOG_TOPIC: usize = 375;
pub const GAS_PER_LOG_DATA_BYTE: usize = 8;
pub const GAS_PER_LOG_DATA_WORD: usize = GAS_PER_LOG_DATA_BYTE * WORD_WIDTH;

// SHARP empirical costs.
pub const SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD: usize = 100; // This value is not accurate.
pub const SHARP_GAS_PER_MEMORY_WORD: usize =
    GAS_PER_MEMORY_WORD + SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD;
// 10% discount for data availability.
pub const DISCOUNT_PER_DA_WORD: usize = (SHARP_GAS_PER_MEMORY_WORD * 10) / 100;
pub const SHARP_GAS_PER_DA_WORD: usize = SHARP_GAS_PER_MEMORY_WORD - DISCOUNT_PER_DA_WORD;
```

**File:** crates/blockifier/src/fee/fee_checks.rs (L88-125)
```rust
            // If the error is resource overdraft, charge for the minimum between (a) actual gas
            // used and (b) the user bound, for each gas type. Pre-validation phase ensures the
            // account balance can pay for maximal amount of each gas type.
            FeeCheckError::MaxGasAmountExceeded { .. } => {
                let TransactionInfo::Current(ref context) = tx_context.tx_info else {
                    panic!("MaxGasAmountExceeded can only originate from a V3 transaction.");
                };
                let gas_for_fee_charge = match context.resource_bounds {
                    // For deprecated resource bounds, the total L1 gas for fee charge includes the
                    // discounted L1 data gas cost.
                    ValidResourceBounds::L1Gas(l1_bounds) => {
                        GasVector::from_l1_gas(l1_bounds.max_amount)
                    }
                    ValidResourceBounds::AllResources(all_resource_bounds) => GasVector {
                        l1_gas: std::cmp::min(
                            all_resource_bounds.l1_gas.max_amount,
                            actual_gas.l1_gas,
                        ),
                        l2_gas: std::cmp::min(
                            all_resource_bounds.l2_gas.max_amount,
                            actual_gas.l2_gas,
                        ),
                        l1_data_gas: std::cmp::min(
                            all_resource_bounds.l1_data_gas.max_amount,
                            actual_gas.l1_data_gas,
                        ),
                    },
                };

                get_fee_by_gas_vector(
                    &tx_context.block_context.block_info,
                    gas_for_fee_charge,
                    &FeeType::Strk,
                    tx_context.effective_tip(),
                )
            }
        };
        Self { recommended_fee, error: Some(error) }
```

**File:** crates/blockifier/src/fee/fee_checks.rs (L277-321)
```rust
impl PostExecutionReport {
    /// Verifies the actual cost can be paid by the account. If not, reports an error and the fee
    /// that should be charged in revert flow.
    pub fn new<S: StateReader>(
        state: &mut S,
        tx_context: &TransactionContext,
        tx_receipt: &TransactionReceipt,
        charge_fee: bool,
    ) -> TransactionExecutionResult<Self> {
        let TransactionReceipt { fee, gas, .. } = tx_receipt;

        // If fee is not enforced, no need to check post-execution.
        if !charge_fee {
            return Ok(Self(FeeCheckReport::success_report(*fee)));
        }

        // First, compare the actual resources used against the upper bound(s) defined by the
        // sender.
        let cost_within_bounds_result =
            FeeCheckReport::check_actual_cost_within_bounds(tx_context, tx_receipt);

        // Next, verify the actual cost is covered by the account balance, which may have changed
        // after execution. If the above check passes, the pre-execution balance covers the actual
        // cost for sure.
        let can_pay_fee_result = FeeCheckReport::check_can_pay_fee(state, tx_context, tx_receipt);

        for fee_check_result in [cost_within_bounds_result, can_pay_fee_result] {
            match fee_check_result {
                Ok(_) => continue,
                Err(TransactionExecutionError::FeeCheckError(fee_check_error)) => {
                    // Found an error; set the recommended fee based on the error variant and
                    // current context, and return the report.
                    return Ok(Self(FeeCheckReport::from_fee_check_error(
                        *fee,
                        *gas,
                        fee_check_error,
                        tx_context,
                    )));
                }
                Err(other_error) => return Err(other_error),
            }
        }

        Ok(Self(FeeCheckReport::success_report(*fee)))
    }
```
