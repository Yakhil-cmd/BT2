### Title
Asymmetric `delta_gas` Adjustment in `compute_gas_refund` Silently Discards User Refund When Native Resource Usage Falls Below EVM Gas Usage - (`basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` applies a one-sided adjustment to `gas_used` based on the difference between native resource consumption and EVM gas consumption (`delta_gas`). When `delta_gas > 0` (native costs exceed gas costs), `gas_used` is increased and the user pays more. When `delta_gas < 0` (gas costs exceed native costs), `gas_used` is **not** decreased, so the user's excess payment is silently discarded and transferred to the operator instead of being refunded. A `TODO` comment in the code explicitly marks this asymmetry as unresolved.

---

### Finding Description

In `compute_gas_refund`, the double resource accounting model computes:

```
delta_gas = (native_used / native_per_gas) - gas_used
``` [1](#0-0) 

The code only handles the `delta_gas > 0` branch — adding `delta_gas` to `gas_used` to ensure native resource costs are covered. The `delta_gas < 0` branch (where EVM gas consumption exceeds native resource consumption) is silently dropped, with a `TODO` comment acknowledging the gap:

```rust
if delta_gas > 0 {
    // In this case, the native resource consumption is more than the
    // gas consumption accounted for. Consume extra gas.
    gas_used += delta_gas as u64;
}
// TODO: return delta_gas to gas_used?
``` [2](#0-1) 

The resulting `gas_used` is then used to compute the user's refund and the operator's payment. For ZK transactions:

- **Refund to user**: `gas_price * (gas_limit - gas_used)`
- **Payment to operator**: `gas_price_for_operator * gas_used` [3](#0-2) [4](#0-3) 

For Ethereum-type transactions, the same `gas_used` drives the refund: [5](#0-4) 

When `delta_gas < 0`, the correct `gas_used` should be `gas_used + delta_gas` (i.e., reduced by `|delta_gas|`), giving the user a larger refund. Instead, `gas_used` remains inflated, the user's refund is smaller than it should be, and the operator receives the difference.

The documentation for the double resource accounting model only describes the `delta_gas > 0` case and is silent on the negative case, confirming this is not an intentional design choice: [6](#0-5) 

---

### Impact Explanation

Every transaction where EVM gas consumption exceeds native resource consumption (computation-heavy, storage-light transactions) results in the user paying more than the actual cost of their transaction. The excess fee — `gas_price * |delta_gas|` — is transferred to the operator (coinbase) rather than refunded to the user. This is a direct, deterministic funds loss for the user on every such transaction, with no attacker action required beyond submitting a normal transaction.

---

### Likelihood Explanation

The `delta_gas < 0` condition is triggered whenever a transaction consumes more EVM gas than native resources. This is a common scenario for computation-heavy but storage-light transactions (e.g., complex arithmetic, large in-memory loops, cryptographic operations that do not write storage). Any unprivileged user submitting such a transaction will be overcharged. The condition is reachable on every block.

---

### Recommendation

Apply the `delta_gas` adjustment symmetrically. When `delta_gas < 0`, decrease `gas_used` by `|delta_gas|` (subject to the `minimal_gas_used` floor) to return the excess to the user:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else if delta_gas < 0 {
    // Native resource consumption is less than gas consumption.
    // Reduce gas_used so the user is refunded the difference.
    gas_used = gas_used.saturating_sub((-delta_gas) as u64);
    gas_used = core::cmp::max(gas_used, minimal_gas_used);
}
```

This makes the native-resource adjustment symmetric and ensures users are neither overcharged nor undercharged relative to actual resource consumption.

---

### Proof of Concept

1. User submits a transaction with `gas_limit = 100_000`, `gas_price = 1000`, `native_per_gas = 5`.
2. Transaction executes and consumes `gas_used_ergs = 60_000` EVM gas and `native_used = 200_000` native units.
3. `native_used / native_per_gas = 40_000`.
4. `delta_gas = 40_000 - 60_000 = -20_000`.
5. Because `delta_gas < 0`, the branch is skipped; `gas_used` remains `60_000`.
6. User refund: `1000 * (100_000 - 60_000) = 40_000_000`.
7. **Correct** refund should be: `1000 * (100_000 - 40_000) = 60_000_000`.
8. User loses `20_000_000` units (= `1000 * 20_000`) that are instead paid to the operator.

The entry path is a standard unprivileged L2 transaction. No special privileges, governance access, or oracle manipulation are required.

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-81)
```rust
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L452-488)
```rust
        if context.tx_gas_limit > context.gas_used {
            system_log!(system, "Gas price for refund is {:?}\n", &context.gas_price);

            // refund
            let refund_recipient = transaction.from();
            let token_to_refund =
                context.gas_price * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow

            // First refund the sender. Routed through `intrinsic_resources` so
            // the native charge (precharged by the intrinsic formula) can be
            // verified under `verify_intrinsic_native`.
            context
                .intrinsic_resources
                .with_infinite_ergs(|resources| {
                    system.io.update_account_nominal_token_balance(
                        ExecutionEnvironmentType::NoEE,
                        resources,
                        &refund_recipient,
                        &token_to_refund,
                        false,
                        Config::SIMULATION,
                    )
                })
                .map_err(|e| match e {
                    // Balance errors can not be cascaded
                    SubsystemError::Cascaded(CascadedError(inner, _)) => match inner {},
                    SubsystemError::LeafUsage(InterfaceError(ie, _)) => match ie {
                        BalanceError::InsufficientBalance => {
                            unreachable!("Cannot be insufficient when incrementing balance")
                        }
                        BalanceError::Overflow => {
                            interface_error!(BootloaderInterfaceError::CantPayRefundOverflow)
                        }
                    },
                    other => wrap_error!(other),
                })?;
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L514-516)
```rust
        let token_to_pay_operator = U256::from(context.gas_used)
            .checked_mul(gas_price_for_operator)
            .ok_or(internal_error!("gu*gpfo"))?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L508-518)
```rust
        if context.tx_gas_limit > context.gas_used {
            system_log!(
                system,
                "Gas price for refund is {:?}\n",
                &context.tx_level_metadata.tx_gas_price
            );

            // refund
            let receiver = transaction.from();
            let refund = context.tx_level_metadata.tx_gas_price
                * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow
```

**File:** docs/double_resource_accounting.md (L47-52)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.

Finally, any remaining gas left is refunded as usual.
```
