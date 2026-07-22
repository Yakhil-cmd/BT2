Let me look at the `GasVector` structure and how `receipt.fee` is computed in blockifier to determine if L2 gas is actually included in the fee.

### Title
`tx_execution_output_to_fee_estimation` Omits `l2_gas_consumed`, Producing Inconsistent `FeeEstimation` for V3 Transactions — (`crates/apollo_rpc_execution/src/objects.rs`)

---

### Summary

`tx_execution_output_to_fee_estimation` constructs a `FeeEstimation` where `overall_fee` is taken from `receipt.fee` — which includes L2 gas cost — but the breakdown fields only expose `gas_consumed` (L1 gas) and `data_gas_consumed` (L1 data gas). The `l2_gas_consumed` field is absent. For any V3 transaction that incurs non-zero L2 gas, the invariant stated in the struct's own docstring (`overall_fee == gas_consumed * l1_gas_price + data_gas_consumed * l1_data_gas_price`) is violated. The RPC returns an authoritative-looking but arithmetically wrong fee breakdown.

---

### Finding Description

**Step 1 — `receipt.fee` includes L2 gas cost.**

`GasVector::cost()` sums all three gas dimensions:

```rust
for (gas, price, resource) in [
    (self.l1_gas,      gas_prices.l1_gas_price,      Resource::L1Gas),
    (self.l1_data_gas, gas_prices.l1_data_gas_price,  Resource::L1DataGas),
    (self.l2_gas,      tipped_l2_gas_price,            Resource::L2Gas),  // ← included
] { ... }
``` [1](#0-0) 

`TransactionReceipt::from_params` calls `tx_context.tx_info.get_fee_by_gas_vector(...)`, which delegates to `gas_vector.cost(...)`, so `receipt.fee = l1_gas * l1_gas_price + l1_data_gas * l1_data_gas_price + l2_gas * l2_gas_price`. [2](#0-1) [3](#0-2) 

**Step 2 — V3 transactions produce non-zero `l2_gas`.**

When `GasVectorComputationMode::All` is active (V3 account transactions), VM resources are converted entirely into L2 gas, not L1 gas:

```rust
GasVectorComputationMode::All => {
    GasVector::from_l2_gas(
        versioned_constants.l1_gas_to_sierra_gas_amount_round_up(l1_gas)
    )
}
``` [4](#0-3) 

So for a V3 transaction, `gas_vector.l2_gas > 0` and `gas_vector.l1_gas ≈ 0` for the computation portion.

**Step 3 — `tx_execution_output_to_fee_estimation` silently drops `l2_gas`.**

```rust
Ok(FeeEstimation {
    gas_consumed:      gas_vector.l1_gas.0.into(),       // L1 gas only
    l1_gas_price,
    data_gas_consumed: gas_vector.l1_data_gas.0.into(),  // L1 data gas only
    l1_data_gas_price,
    l2_gas_price,                                        // price present, amount absent
    overall_fee: tx_execution_output.execution_info.receipt.fee,  // includes L2 cost
    unit: tx_execution_output.price_unit,
})
``` [5](#0-4) 

The `FeeEstimation` struct's own docstring asserts the invariant that is broken:

```
/// The total amount of fee. This is equal to:
/// gas_consumed * gas_price + data_gas_consumed * data_gas_price.
``` [6](#0-5) 

The TODO comment confirms the gap is known but unresolved:

```
// TODO(Tzahi): Add l2_gas_consumed. Verify overall_fee estimation of l1_gas_price only is
// close enough (as there are roundings) to the fee of both l1_gas_price and l2_gas_price.
``` [7](#0-6) 

---

### Impact Explanation

Any caller of `starknet_estimateFee` or `starknet_simulateTransactions` with a V3 transaction receives a `FeeEstimation` where:

```
overall_fee  ≠  gas_consumed * l1_gas_price + data_gas_consumed * l1_data_gas_price
```

The gap equals `l2_gas * l2_gas_price`, which is the dominant cost component for compute-heavy V3 transactions. Clients that reconstruct resource bounds from the breakdown (rather than from `overall_fee`) will compute values that are too low, potentially causing their submitted transactions to fail fee checks. The response is authoritative-looking (it comes from the node's own execution engine with a docstring claiming the equality holds), satisfying the **High** impact criterion: *RPC execution, fee estimation, tracing, or simulation returns an authoritative-looking wrong value*.

---

### Likelihood Explanation

Every V3 `INVOKE`, `DECLARE`, or `DEPLOY_ACCOUNT` transaction that executes any Cairo code triggers `GasVectorComputationMode::All`, producing non-zero `l2_gas`. This is the normal operating mode for all post-0.13 account transactions. No special crafting is required; the discrepancy is structural and reproducible with any standard V3 transaction.

---

### Recommendation

Add `l2_gas_consumed: gas_vector.l2_gas.0.into()` to the `FeeEstimation` struct and populate it in `tx_execution_output_to_fee_estimation`. Update the `overall_fee` docstring to reflect the three-component sum. Clients should be able to verify: `overall_fee == gas_consumed * l1_gas_price + data_gas_consumed * l1_data_gas_price + l2_gas_consumed * l2_gas_price`.

---

### Proof of Concept

A Rust unit test can confirm the discrepancy:

1. Execute any V3 `InvokeTransaction` through `execute_transactions` (with `charge_fee=false`, `validate=false`).
2. Call `tx_execution_output_to_fee_estimation` on the result.
3. Assert:
   ```rust
   let reconstructed = fee_estimation.gas_consumed * fee_estimation.l1_gas_price
       + fee_estimation.data_gas_consumed * fee_estimation.l1_data_gas_price;
   assert_eq!(reconstructed, fee_estimation.overall_fee.0,
       "L2 gas cost missing from breakdown: overall_fee={}, reconstructed={}",
       fee_estimation.overall_fee.0, reconstructed);
   ```
4. The assertion fails because `overall_fee` includes `l2_gas * l2_gas_price` while `reconstructed` does not.

### Citations

**File:** crates/starknet_api/src/execution_resources.rs (L156-186)
```rust
    pub fn cost(&self, gas_prices: &GasPriceVector, tip: Tip) -> Fee {
        let tipped_l2_gas_price =
            gas_prices.l2_gas_price.checked_add(tip.into()).unwrap_or_else(|| {
                panic!(
                    "Tip overflowed: addition of L2 gas price ({}) and tip ({}) resulted in \
                     overflow.",
                    gas_prices.l2_gas_price, tip
                )
            });

        let mut sum = Fee(0);
        for (gas, price, resource) in [
            (self.l1_gas, gas_prices.l1_gas_price, Resource::L1Gas),
            (self.l1_data_gas, gas_prices.l1_data_gas_price, Resource::L1DataGas),
            (self.l2_gas, tipped_l2_gas_price, Resource::L2Gas),
        ] {
            let cost = gas.checked_mul(price.get()).unwrap_or_else(|| {
                panic!(
                    "{resource} cost overflowed: multiplication of gas amount ({gas}) by price \
                     per unit ({price}) resulted in overflow."
                )
            });
            sum = sum.checked_add(cost).unwrap_or_else(|| {
                panic!(
                    "Total cost overflowed: addition of current sum ({sum}) and cost of \
                     {resource} ({cost}) resulted in overflow."
                )
            });
        }
        sum
    }
```

**File:** crates/blockifier/src/fee/receipt.rs (L111-119)
```rust
        let fee = if tx_type == TransactionType::Declare && tx_context.tx_info.is_v0() {
            Fee(0)
        } else {
            tx_context.tx_info.get_fee_by_gas_vector(
                &tx_context.block_context.block_info,
                gas,
                tx_context.effective_tip(),
            )
        };
```

**File:** crates/blockifier/src/fee/fee_utils.rs (L130-135)
```rust
    match computation_mode {
        GasVectorComputationMode::NoL2Gas => GasVector::from_l1_gas(l1_gas),
        GasVectorComputationMode::All => {
            GasVector::from_l2_gas(versioned_constants.l1_gas_to_sierra_gas_amount_round_up(l1_gas))
        }
    }
```

**File:** crates/blockifier/src/fee/fee_utils.rs (L139-146)
```rust
pub fn get_fee_by_gas_vector(
    block_info: &BlockInfo,
    gas_vector: GasVector,
    fee_type: &FeeType,
    tip: Tip,
) -> Fee {
    gas_vector.cost(block_info.gas_prices.gas_price_vector(fee_type), tip)
}
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L104-106)
```rust
    // TODO(Tzahi): Add l2_gas_consumed. Verify overall_fee estimation of l1_gas_price only is
    // close enough (as there are roundings) to the fee of both l1_gas_price and l2_gas_price.
    /// The L2 gas price for execution.
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L108-110)
```rust
    /// The total amount of fee. This is equal to:
    /// gas_consumed * gas_price + data_gas_consumed * data_gas_price.
    pub overall_fee: Fee,
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L161-183)
```rust
pub(crate) fn tx_execution_output_to_fee_estimation(
    tx_execution_output: &TransactionExecutionOutput,
    block_context: &BlockContext,
) -> ExecutionResult<FeeEstimation> {
    let gas_prices = &block_context.block_info().gas_prices;
    let (l1_gas_price, l1_data_gas_price, l2_gas_price) = (
        gas_prices.l1_gas_price(&tx_execution_output.price_unit.into()).get(),
        gas_prices.l1_data_gas_price(&tx_execution_output.price_unit.into()).get(),
        gas_prices.l2_gas_price(&tx_execution_output.price_unit.into()).get(),
    );

    let gas_vector = tx_execution_output.execution_info.receipt.gas;

    Ok(FeeEstimation {
        gas_consumed: gas_vector.l1_gas.0.into(),
        l1_gas_price,
        data_gas_consumed: gas_vector.l1_data_gas.0.into(),
        l1_data_gas_price,
        l2_gas_price,
        overall_fee: tx_execution_output.execution_info.receipt.fee,
        unit: tx_execution_output.price_unit,
    })
}
```
