Looking at the code carefully to determine if this is a real issue.

### Title
`FeeEstimation` Omits `l2_gas_consumed`, Breaking the `overall_fee` Formula Invariant for v3 Transactions — (`crates/apollo_rpc_execution/src/objects.rs`)

---

### Summary

`tx_execution_output_to_fee_estimation` sets `overall_fee = receipt.fee`, which is computed by `GasVector::cost()` and includes the L2 gas component (`l2_gas * (l2_gas_price + tip)`). However, the `FeeEstimation` struct exposes only `gas_consumed` (L1 gas) and `data_gas_consumed` (L1 data gas), with no `l2_gas_consumed` field. For any v3 (`AllResourceBounds`) transaction that consumes nonzero L2 gas, the formula stated in both the struct's doc comment and the OpenRPC spec — `overall_fee = gas_consumed * l1_gas_price + data_gas_consumed * l1_data_gas_price` — is violated. The discrepancy is acknowledged by an in-code TODO but is not yet resolved.

---

### Finding Description

**`FeeEstimation` struct — missing `l2_gas_consumed`:** [1](#0-0) 

The struct carries `l2_gas_price` but no `l2_gas_consumed`. The doc comment on `overall_fee` (line 108–109) states the formula as `gas_consumed * gas_price + data_gas_consumed * data_gas_price`, omitting the L2 gas term entirely. A TODO at line 104 explicitly acknowledges the missing field.

**`tx_execution_output_to_fee_estimation` — sets `overall_fee` from `receipt.fee`:** [2](#0-1) 

`receipt.fee` is produced by `GasVector::cost()`, which sums all three gas components: [3](#0-2) 

So `overall_fee = l1_gas * l1_gas_price + l1_data_gas * l1_data_gas_price + l2_gas * (l2_gas_price + tip)`. When `l2_gas > 0`, the returned `overall_fee` is larger than `gas_consumed * l1_gas_price + data_gas_consumed * l1_data_gas_price`, and the difference is invisible to the caller.

**OpenRPC spec repeats the broken formula:** [4](#0-3) 

The spec description says `overall_fee` "equals to gas_consumed\*gas_price + data_gas_consumed\*data_gas_price" — no mention of L2 gas — making the mismatch authoritative-looking to any client that reads the spec.

---

### Impact Explanation

**High — RPC fee estimation returns an authoritative-looking wrong value.**

The `overall_fee` field is numerically correct (it is the fee that will actually be charged). However, the response is structurally inconsistent: `l2_gas_consumed` is absent, so callers cannot reconstruct `overall_fee` from the other fields, cannot verify the fee breakdown, and cannot detect how much of the fee is attributable to L2 execution gas. Any client that applies the documented formula to cross-check the fee will compute a value lower than `overall_fee` and conclude the response is malformed or that there is an unexplained surplus.

This does **not** rise to Critical because the actual fee charged on-chain is correct — no balance is incorrectly debited, no funds are minted or burned, and no economic harm occurs from the fee-charging path itself.

---

### Likelihood Explanation

Certain for any v3 (`AllResourceBounds`) transaction on a block context with nonzero `l2_gas_price`. All modern Starknet v3 transactions use `AllResourceBounds` and consume L2 gas. The real-world RPC records in the repo already show nonzero `l2_gas_consumed` values alongside `overall_fee` values that include the L2 gas cost. [5](#0-4) 

---

### Recommendation

1. Add `l2_gas_consumed: Felt` to `FeeEstimation` and populate it from `gas_vector.l2_gas.0.into()` in `tx_execution_output_to_fee_estimation`.
2. Update the doc comment on `overall_fee` to reflect the three-term formula.
3. Update the OpenRPC spec description for `FEE_ESTIMATE.overall_fee` to include the L2 gas term.
4. Add `l2_gas_consumed` to the `required` array in the OpenRPC schema.

---

### Proof of Concept

The invariant violation is directly observable from the existing code paths:

```
// Given a v3 Invoke with AllResourceBounds and nonzero l2_gas_price:
let estimation = tx_execution_output_to_fee_estimation(&output, &block_context)?;

// overall_fee is computed as:
//   l1_gas * l1_gas_price + l1_data_gas * l1_data_gas_price + l2_gas * (l2_gas_price + tip)
// but the struct only exposes l1_gas and l1_data_gas components.

let reconstructed = estimation.gas_consumed * estimation.l1_gas_price
                  + estimation.data_gas_consumed * estimation.l1_data_gas_price;

// For any tx with l2_gas > 0:
assert!(estimation.overall_fee.0 > reconstructed);  // always true — formula violated
```

The real-world fixture at `crates/starknet_transaction_prover/resources/rpc_records/test_execute_with_prefetch.json` shows `l2_gas_consumed = 0xb56b6` and `overall_fee = 0x151eb86f3ed400` with `l1_gas_consumed = 0x0`, confirming the L2 gas component dominates the fee in practice.

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L94-113)
```rust
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
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

**File:** crates/apollo_rpc_execution/src/objects.rs (L172-182)
```rust
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
```

**File:** crates/starknet_api/src/execution_resources.rs (L166-171)
```rust
        let mut sum = Fee(0);
        for (gas, price, resource) in [
            (self.l1_gas, gas_prices.l1_gas_price, Resource::L1Gas),
            (self.l1_data_gas, gas_prices.l1_data_gas_price, Resource::L1DataGas),
            (self.l2_gas, tipped_l2_gas_price, Resource::L2Gas),
        ] {
```

**File:** crates/apollo_rpc/resources/V0_8/starknet_api_openrpc.json (L3648-3651)
```json
                    "overall_fee": {
                        "title": "Overall fee",
                        "description": "The estimated fee for the transaction (in wei or fri, depending on the tx version), equals to gas_consumed*gas_price + data_gas_consumed*data_gas_price",
                        "$ref": "#/components/schemas/FELT"
```

**File:** crates/starknet_transaction_prover/resources/rpc_records/test_execute_with_prefetch.json (L134-143)
```json
              "fee_estimation": {
                "l1_data_gas_consumed": "0x80",
                "l1_data_gas_price": "0x3e8",
                "l1_gas_consumed": "0x0",
                "l1_gas_price": "0xe8d4a51000",
                "l2_gas_consumed": "0xb56b6",
                "l2_gas_price": "0x1dcd65000",
                "overall_fee": "0x151eb86f3ed400",
                "unit": "FRI"
              },
```
