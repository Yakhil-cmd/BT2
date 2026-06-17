### Title
One-Sided `delta_gas` Adjustment in `compute_gas_refund` Causes User Overcharge — (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` computes a signed `delta_gas` value representing the difference between native-resource-implied gas and EVM gas used, but only applies the adjustment in one direction (`delta_gas > 0`). When `delta_gas < 0` — meaning native resource consumption is *cheaper* than EVM gas consumption — the function silently skips the downward correction, leaving `gas_used` inflated. Users are therefore overcharged: they receive a smaller gas refund than their actual resource consumption warrants. A developer `// TODO` comment in the same block explicitly acknowledges this asymmetry.

---

### Finding Description

In `compute_gas_refund`, after computing `native_used` and `gas_used`, the function calculates:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};

if delta_gas > 0 {
    // native resource consumption is more than EVM gas accounted for → charge extra
    gas_used += delta_gas as u64;
}
// TODO: return delta_gas to gas_used?
``` [1](#0-0) 

The `delta_gas` value is a **signed** `i64`, so it can be negative. The negative case (`delta_gas < 0`) means the native resource consumption implied fewer gas units than the EVM gas counter recorded. In that scenario, `gas_used` should be reduced by `|delta_gas|` to give the user a proportionally larger refund. Instead, the branch is entirely absent — the `// TODO: return delta_gas to gas_used?` comment is the only acknowledgement of this gap.

The final refund is computed as:

```rust
let total_gas_refund = gas_limit - gas_used;
``` [2](#0-1) 

Because `gas_used` is not reduced when `delta_gas < 0`, `total_gas_refund` is smaller than it should be, and the user is charged for gas they did not effectively consume.

This function is called from both the ZK L2 transaction flow (`before_refund`) and the L1 transaction flow (`process_l1_transaction`): [3](#0-2) [4](#0-3) 

The double-resource-accounting model is documented to apply `delta_gas` only when positive: [5](#0-4) 

The documentation itself only describes the positive case, confirming the negative case is unhandled.

---

### Impact Explanation

When a transaction's native resource consumption is lower than its EVM gas consumption (i.e., `native_used / native_per_gas < gas_used`), the user's `gas_used` is not reduced. The refund paid back to the sender is:

```
refund = (gas_limit - gas_used) * gas_price
``` [6](#0-5) 

With an inflated `gas_used`, the refund is smaller than it should be. The operator receives the excess. This is a direct financial loss for the transaction sender — they pay more than their actual resource consumption warrants. The magnitude scales with `|delta_gas| * gas_price`.

---

### Likelihood Explanation

Any transaction where EVM gas consumption exceeds the native-resource-equivalent gas triggers this path. Concretely:

- Transactions with many `SLOAD`/`SSTORE` operations are expensive in EVM gas (2100–20000 gas each) but may be relatively cheap in native (proving) resources.
- Transactions that hit the EVM gas refund cap (EIP-3529, 1/5 of gas used) reduce `gas_used` before the delta check, making it more likely that `gas_used` exceeds the native equivalent.
- Any unprivileged L2 or L1→L2 transaction sender can trigger this path without any special access.

The `// TODO` comment confirms the developers are aware of the asymmetry but have not resolved it. [7](#0-6) 

---

### Recommendation

Apply the `delta_gas` correction symmetrically. When `delta_gas < 0`, reduce `gas_used` (floored at `minimal_gas_used` to preserve the intrinsic-cost invariant):

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else if delta_gas < 0 {
    let reduction = (-delta_gas) as u64;
    gas_used = gas_used.saturating_sub(reduction).max(minimal_gas_used);
}
```

This mirrors the intent described in the double-resource-accounting documentation and eliminates the asymmetric overcharge.

---

### Proof of Concept

1. Deploy a contract that performs many `SLOAD` operations (high EVM gas, low native cost).
2. Submit an L2 transaction calling that contract with a `gas_price` such that `native_per_gas > 0`.
3. After execution, observe that `gas_used` reported equals the EVM gas consumed, not the lower native-equivalent value.
4. Compute `expected_gas_used = native_used / native_per_gas`. Confirm `gas_used > expected_gas_used`.
5. Confirm the refund paid to the sender is `(gas_limit - gas_used) * gas_price` rather than `(gas_limit - expected_gas_used) * gas_price`, demonstrating the overcharge.

The existing test `test_delta_gas` in `tests/instances/transactions/src/native_charging.rs` only tests the positive-delta path (native more expensive than EVM gas) and does not cover the negative-delta scenario. [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L66-81)
```rust
    #[cfg(not(feature = "unlimited_native"))]
    {
        // Adjust gas_used with difference with used native
        let delta_gas = if native_per_gas == 0 {
            0
        } else {
            (native_used / native_per_gas) as i64 - (gas_used as i64)
        };

        if delta_gas > 0 {
            // In this case, the native resource consumption is more than the
            // gas consumption accounted for. Consume extra gas.
            gas_used += delta_gas as u64;
        }
        // TODO: return delta_gas to gas_used?
    }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L83-83)
```rust
    let total_gas_refund = gas_limit - gas_used;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L427-434)
```rust
        let refund_info = compute_gas_refund(
            system,
            to_charge_for_pubdata,
            transaction.gas_limit(),
            min_gas_used,
            context.native_per_gas,
            &mut context.resources.main_resources,
        )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L452-458)
```rust
        if context.tx_gas_limit > context.gas_used {
            system_log!(system, "Gas price for refund is {:?}\n", &context.gas_price);

            // refund
            let refund_recipient = transaction.from();
            let token_to_refund =
                context.gas_price * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L262-273)
```rust
    let RefundInfo {
        gas_used,
        evm_refund,
        native_used,
    } = compute_gas_refund(
        system,
        to_charge_for_pubdata,
        gas_limit,
        minimal_gas_used,
        native_per_gas,
        &mut resources,
    )?;
```

**File:** docs/double_resource_accounting.md (L47-51)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.

```

**File:** tests/instances/transactions/src/native_charging.rs (L410-452)
```rust
// Test delta gas, pass lower ratio
#[test]
fn test_delta_gas() {
    let wallet = testing_signer(0);
    let native_price = 100;
    // Low enough that tx will fail without priority fee
    let ratio = 20;
    let gas_price = native_price * ratio;
    // First tx, no priority fee, should fail
    let tx = {
        let tx = TxEip1559 {
            chain_id: 37u64,
            nonce: 0,
            max_fee_per_gas: gas_price.into(),
            max_priority_fee_per_gas: gas_price.into(),
            gas_limit: 60_000,
            to: TxKind::Call(TO),
            value: Default::default(),
            access_list: Default::default(),
            input: hex::decode(ERC_20_TRANSFER_CALLDATA).unwrap().into(),
        };
        ZKsyncTxEnvelope::from_eth_tx(tx, wallet.clone())
    };
    // Should fail
    run_tx(tx, gas_price, native_price, false, false);
    // Second tx, high priority fee, should succeed
    let tx = {
        let tx = TxEip1559 {
            chain_id: 37u64,
            nonce: 0,
            max_fee_per_gas: (5 * gas_price).into(),
            max_priority_fee_per_gas: (5 * gas_price).into(),
            gas_limit: 60_000,
            to: TxKind::Call(TO),
            value: Default::default(),
            access_list: Default::default(),
            input: hex::decode(ERC_20_TRANSFER_CALLDATA).unwrap().into(),
        };
        ZKsyncTxEnvelope::from_eth_tx(tx, wallet.clone())
    };
    // Should succeed
    run_tx(tx, gas_price, native_price, true, false)
}
```
