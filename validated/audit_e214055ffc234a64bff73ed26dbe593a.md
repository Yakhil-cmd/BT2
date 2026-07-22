### Title
`FeeEstimation` RPC Response Omits `l2_gas_consumed`, Returning an Authoritative-Looking Wrong Fee Breakdown for V3 Transactions — (`File: crates/apollo_rpc_execution/src/objects.rs`)

---

### Summary

The `tx_execution_output_to_fee_estimation` function returns a `FeeEstimation` object that includes `l2_gas_price` but silently omits `l2_gas_consumed`. For any V3 transaction that consumes L2 gas, the `overall_fee` field (taken from the execution receipt) correctly includes the L2 gas cost, but the per-component breakdown does not. The documented formula for `overall_fee` — `gas_consumed * gas_price + data_gas_consumed * data_gas_price` — is therefore wrong for every V3 transaction, and clients have no way to derive `l2_gas_consumed` from the response.

---

### Finding Description

`FeeEstimation` is defined in `crates/apollo_rpc_execution/src/objects.rs`:

```rust
pub struct FeeEstimation {
    pub gas_consumed: Felt,          // l1_gas
    pub l1_gas_price: GasPrice,
    pub data_gas_consumed: Felt,     // l1_data_gas
    pub l1_data_gas_price: GasPrice,
    // TODO(Tzahi): Add l2_gas_consumed. Verify overall_fee estimation of l1_gas_price only is
    // close enough (as there are roundings) to the fee of both l1_gas_price and l2_gas_price.
    pub l2_gas_price: GasPrice,      // price present, quantity absent
    pub overall_fee: Fee,
    pub unit: PriceUnit,
}
``` [1](#0-0) 

The function that populates this struct:

```rust
Ok(FeeEstimation {
    gas_consumed: gas_vector.l1_gas.0.into(),
    l1_gas_price,
    data_gas_consumed: gas_vector.l1_data_gas.0.into(),
    l1_data_gas_price,
    l2_gas_price,
    // gas_vector.l2_gas is never read here
    overall_fee: tx_execution_output.execution_info.receipt.fee,
    unit: tx_execution_output.price_unit,
})
``` [2](#0-1) 

The `overall_fee` is taken directly from `receipt.fee`. The receipt fee is computed by `GasVector::cost()`, which sums all three resources:

```rust
for (gas, price, resource) in [
    (self.l1_gas,      gas_prices.l1_gas_price,      Resource::L1Gas),
    (self.l1_data_gas, gas_prices.l1_data_gas_price,  Resource::L1DataGas),
    (self.l2_gas,      tipped_l2_gas_price,           Resource::L2Gas),
] { ... }
``` [3](#0-2) 

So `overall_fee = l1_gas*l1_gas_price + l1_data_gas*l1_data_gas_price + l2_gas*l2_gas_price`, but the struct docstring and the OpenRPC spec both declare:

> "equals to gas_consumed\*gas_price + data_gas_consumed\*data_gas_price" [4](#0-3) 

The L2 gas term is entirely absent from the documented formula, yet it is silently included in `overall_fee`. The response exposes `l2_gas_price` but not `l2_gas_consumed`, so callers have no way to reconcile the discrepancy.

---

### Impact Explanation

Every call to `starknet_estimateFee` or `starknet_simulateTransactions` for a V3 transaction returns a response where:

1. **`overall_fee` is numerically correct** (it comes from the receipt and includes L2 gas cost).
2. **The documented formula is wrong**: `gas_consumed * l1_gas_price + data_gas_consumed * l1_data_gas_price` produces a value that is strictly less than `overall_fee` by exactly `l2_gas_consumed * l2_gas_price`.
3. **`l2_gas_consumed` is absent**: clients cannot determine how much L2 gas was used, so they cannot set a correct `max_l2_gas` resource bound for the real transaction.

A client that trusts the formula to reconstruct the fee will compute a systematically underestimated value. A client that uses the response to size `max_l2_gas` has no data to work with and must guess, leading either to rejected transactions (bound too low) or unnecessary overpayment (bound too high). This matches the **High** impact category: *RPC fee estimation returns an authoritative-looking wrong value*.

---

### Likelihood Explanation

This affects every V3 (`AllResources`) transaction submitted to the sequencer. The Starknet ecosystem has been migrating to V3 transactions as the default. Any wallet, SDK, or dApp that calls `starknet_estimateFee` and uses the component breakdown (rather than blindly forwarding `overall_fee`) will be affected.

---

### Recommendation

1. Add `l2_gas_consumed: Felt` to `FeeEstimation`.
2. Populate it in `tx_execution_output_to_fee_estimation`:
   ```rust
   l2_gas_consumed: gas_vector.l2_gas.0.into(),
   ```
3. Update the `overall_fee` docstring and the OpenRPC spec description to include the L2 gas term: `gas_consumed*l1_gas_price + data_gas_consumed*l1_data_gas_price + l2_gas_consumed*l2_gas_price`.

---

### Proof of Concept

1. Submit any V3 invoke transaction to `starknet_estimateFee`.
2. Observe the response: `l2_gas_price` is non-zero, but `l2_gas_consumed` is absent.
3. Compute `gas_consumed * l1_gas_price + data_gas_consumed * l1_data_gas_price`.
4. Compare to `overall_fee` — the result is lower by `l2_gas * l2_gas_price`.
5. Attempt to set `max_l2_gas` for the real transaction: there is no field in the response to derive this value from.

The TODO comment at line 104 of `objects.rs` confirms the developers are aware the field is missing and that the `overall_fee` formula is only an approximation — but the approximation is presented to callers as exact. [5](#0-4)

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L95-113)
```rust
pub struct FeeEstimation {
    /// Gas consumed by this transaction. This includes gas for DA in calldata mode.
    pub gas_consumed: Felt,
    /// The gas price for execution and calldata DA.
    pub l1_gas_price: GasPrice,
    /// Gas consumed by DA in blob mode.
    pub data_gas_consumed: Felt,
    /// The gas price for DA blob.
    pub l1_data_gas_price: GasPrice,
    // TODO(Tzahi): Add l2_gas_consumed. Verify overall_fee estimation of l1_gas_price only is
    // close enough (as there are roundings) to the fee of both l1_gas_price and l2_gas_price.
    /// The L2 gas price for execution.
    pub l2_gas_price: GasPrice,
    /// The total amount of fee. This is equal to:
    /// gas_consumed * gas_price + data_gas_consumed * data_gas_price.
    pub overall_fee: Fee,
    /// The unit in which the fee was paid (Wei/Fri).
    pub unit: PriceUnit,
}
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

**File:** crates/apollo_rpc/resources/V0_8/starknet_api_openrpc.json (L3648-3652)
```json
                    "overall_fee": {
                        "title": "Overall fee",
                        "description": "The estimated fee for the transaction (in wei or fri, depending on the tx version), equals to gas_consumed*gas_price + data_gas_consumed*data_gas_price",
                        "$ref": "#/components/schemas/FELT"
                    },
```
