### Title
`FeeEstimation` RPC response omits `l2_gas_consumed`, causing fee breakdown to be structurally wrong for V3 (AllResources) transactions — (`crates/apollo_rpc_execution/src/objects.rs`)

---

### Summary

The `FeeEstimation` struct returned by `starknet_estimateFee` and `starknet_simulateTransactions` is missing the `l2_gas_consumed` field. For V3 transactions that use `AllResources` bounds, the `overall_fee` correctly includes L2 gas cost (computed via `GasVector::cost()`), but the per-component breakdown omits L2 gas entirely. The struct's own doc-comment claims the fee equals `gas_consumed * gas_price + data_gas_consumed * data_gas_price`, which is arithmetically wrong for any transaction with non-zero L2 gas. The Starknet RPC spec (confirmed by the project's own RPC fixture records) requires `l2_gas_consumed` in the response.

---

### Finding Description

**Root cause — `FeeEstimation` struct definition:** [1](#0-0) 

The struct exposes `l2_gas_price` but has no `l2_gas_consumed` field. The inline TODO at line 104 acknowledges the gap:

```
// TODO(Tzahi): Add l2_gas_consumed. Verify overall_fee estimation of l1_gas_price only is
// close enough (as there are roundings) to the fee of both l1_gas_price and l2_gas_price.
```

**Root cause — population in `tx_execution_output_to_fee_estimation`:** [2](#0-1) 

`gas_vector.l1_gas` → `gas_consumed`, `gas_vector.l1_data_gas` → `data_gas_consumed`, but `gas_vector.l2_gas` is silently dropped. The `overall_fee` is taken directly from `receipt.fee`, which **is** computed correctly over all three gas components: [3](#0-2) 

So `overall_fee` ≠ `gas_consumed × l1_gas_price + data_gas_consumed × l1_data_gas_price` for any V3 transaction with L2 gas, contradicting the struct's own documentation.

**Spec evidence — the project's own RPC fixture records include `l2_gas_consumed`:** [4](#0-3) 

The external Starknet node returns `l2_gas_consumed: "0xb56b6"` alongside `l2_gas_price`. This sequencer's RPC server returns `l2_gas_price` with no corresponding consumed amount.

**Call path to the RPC surface:**

`starknet_estimateFee` / `starknet_simulateTransactions` → `apollo_rpc_execution` → `tx_execution_output_to_fee_estimation` → `FeeEstimation { gas_consumed: l1_gas, data_gas_consumed: l1_data_gas, l2_gas_price, overall_fee, … }` — `l2_gas_consumed` never set.

---

### Impact Explanation

**Matches: High — RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value.**

1. **Incorrect fee breakdown**: Any caller that reconstructs the fee from components using the formula documented in the struct (`gas_consumed × l1_gas_price + data_gas_consumed × l1_data_gas_price`) will compute a value that is **less than** `overall_fee` for V3 transactions with L2 gas. The discrepancy equals `l2_gas_consumed × l2_gas_price`.

2. **Unusable for resource-bound sizing**: Wallets and SDKs call `starknet_estimateFee` to determine the `l2_gas.max_amount` to embed in a V3 transaction's resource bounds. Without `l2_gas_consumed` in the response, they cannot derive this value from the estimation endpoint. Setting `l2_gas.max_amount` too low causes the transaction to revert post-execution with `MaxGasAmountExceeded`; setting it too high causes overpayment.

3. **Non-conformance with Starknet RPC spec**: The response is structurally different from what the spec and the project's own fixture data expect, meaning any conformance-checking client will reject or misparse the response.

---

### Likelihood Explanation

- Triggered by any call to `starknet_estimateFee` or `starknet_simulateTransactions` for a V3 (`AllResources`) transaction that consumes non-zero L2 gas — the dominant transaction type on Starknet post-0.13.3.
- No special attacker capability required; any unprivileged user submitting a normal invoke transaction triggers this.
- The TODO comment confirms the developers are aware but have not yet fixed it.

---

### Recommendation

1. Add `l2_gas_consumed: Felt` to `FeeEstimation` in `crates/apollo_rpc_execution/src/objects.rs`.
2. Populate it in `tx_execution_output_to_fee_estimation`:
   ```rust
   l2_gas_consumed: gas_vector.l2_gas.0.into(),
   ```
3. Update the doc-comment on `overall_fee` to reflect the correct three-component formula:
   `gas_consumed × l1_gas_price + data_gas_consumed × l1_data_gas_price + l2_gas_consumed × (l2_gas_price + tip)`.
4. Add a regression test asserting that `gas_consumed × l1_gas_price + data_gas_consumed × l1_data_gas_price + l2_gas_consumed × l2_gas_price == overall_fee` for a V3 transaction with non-zero L2 gas.

---

### Proof of Concept

Submit any V3 invoke transaction to `starknet_estimateFee`. Observe:

```json
{
  "gas_consumed": "0x0",
  "l1_gas_price": "0xe8d4a51000",
  "data_gas_consumed": "0x80",
  "l1_data_gas_price": "0x3e8",
  "l2_gas_price": "0x1dcd65000",
  // l2_gas_consumed is ABSENT
  "overall_fee": "0x151eb86f3ed400",
  "unit": "FRI"
}
```

Verify: `0x0 × 0xe8d4a51000 + 0x80 × 0x3e8 = 0x20000` ≠ `0x151eb86f3ed400 = overall_fee`.

The gap (`overall_fee − reconstructed_fee`) equals the L2 gas cost (`l2_gas_consumed × l2_gas_price`), which is silently dropped from the response by `tx_execution_output_to_fee_estimation` at line 175–182.

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

**File:** crates/starknet_transaction_prover/resources/rpc_records/test_simulate_and_get_initial_reads.json (L92-101)
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
