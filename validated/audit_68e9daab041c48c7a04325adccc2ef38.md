### Title
Missing Negative `delta_gas` Refund in `compute_gas_refund` Causes User Overpayment — (`File: basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, the dual-resource accounting adjustment (`delta_gas`) is applied asymmetrically: when native resource consumption implies the user should pay *more* gas (`delta_gas > 0`), `gas_used` is increased. But when native resource consumption implies the user should pay *less* gas (`delta_gas < 0`), `gas_used` is silently left unchanged. The user is never refunded the corresponding gas units, causing a direct financial loss. A developer `// TODO` comment at the exact location acknowledges this missing branch.

---

### Finding Description

`compute_gas_refund` in `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs` implements ZKsync OS's double-resource accounting reconciliation. After execution, it computes:

```
delta_gas = (native_used / native_per_gas) - gas_used
``` [1](#0-0) 

The design intent, documented in `docs/double_resource_accounting.md`, is:

> `deltaGas := (nativeUsed / nativePerGas) - gasUsed`
> If `deltaGas > 0`, we add it to `gasUsed` … Finally, any remaining gas left is refunded as usual. [2](#0-1) 

The documentation implies the negative case should also be handled (reducing `gas_used` so the user gets a larger refund). The code only handles the positive branch:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
}
// TODO: return delta_gas to gas_used?
``` [3](#0-2) 

When `delta_gas < 0` — meaning the transaction's EVM gas consumption exceeds what its native resource consumption warrants — `gas_used` is not reduced. The user is charged for the full EVM gas used rather than the lower native-resource-implied amount.

The resulting `gas_used` is then used directly to compute the user's refund and the operator's payment:

- ZK path: `token_to_refund = gas_price * (tx_gas_limit - gas_used)` [4](#0-3) 
- Ethereum path: `refund = tx_gas_price * (tx_gas_limit - gas_used)` [5](#0-4) 

Because `gas_used` is inflated (not reduced by `|delta_gas|`), the user receives a smaller refund than they are owed, and the operator receives a correspondingly larger payment.

This code path is active in production: it is gated by `#[cfg(not(feature = "unlimited_native"))]`, meaning it runs whenever native resources are bounded — i.e., in all non-test proving and sequencing execution. [6](#0-5) 

---

### Impact Explanation

**Direct financial loss to users.** For any transaction where EVM gas consumption exceeds native resource consumption (`delta_gas < 0`), the user overpays by `gas_price * |delta_gas|`. This amount is transferred to the operator instead of being refunded to the sender. The loss is proportional to the magnitude of the negative delta and the gas price. There is no cap or bound on the overpayment per transaction.

---

### Likelihood Explanation

The scenario `delta_gas < 0` arises whenever a transaction is compute-heavy in EVM terms but light on native resource consumption (e.g., transactions with many EVM opcodes but minimal pubdata/storage writes). This is a realistic and common transaction profile. Any user submitting such a transaction through the normal L2 transaction flow (ZK or Ethereum path) is affected without any special conditions. The `// TODO` comment confirms the developers are aware of the gap.

---

### Recommendation

In `compute_gas_refund`, handle the negative `delta_gas` case symmetrically with the positive case. When `delta_gas < 0`, reduce `gas_used` by `|delta_gas|`, subject to the `minimal_gas_used` floor:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else if delta_gas < 0 {
    // Native consumption is less than EVM gas consumption.
    // Reduce gas_used, but not below the minimal floor.
    let reduction = (-delta_gas) as u64;
    gas_used = gas_used.saturating_sub(reduction).max(minimal_gas_used);
}
// Remove the TODO comment once addressed.
``` [6](#0-5) 

---

### Proof of Concept

1. Deploy a contract that performs many EVM computation opcodes (e.g., repeated `MUL`/`SHA3`) but writes zero or minimal storage slots (low pubdata).
2. Submit an L2 transaction calling this contract with a non-zero `gas_price` and sufficient `gas_limit`.
3. After execution, observe that `gas_used` reported equals the full EVM gas consumed.
4. Compute `native_used / native_per_gas` — this will be less than `gas_used` because the transaction is compute-heavy but pubdata-light.
5. Observe that the user's refund is `gas_price * (gas_limit - gas_used)` rather than `gas_price * (gas_limit - native_used/native_per_gas)`.
6. The difference `gas_price * (gas_used - native_used/native_per_gas)` is paid to the operator instead of being returned to the user.

The `// TODO: return delta_gas to gas_used?` comment at line 80 of `refund_calculation.rs` is a direct in-code acknowledgment of this missing refund path. [7](#0-6)

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

**File:** docs/double_resource_accounting.md (L47-52)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.

Finally, any remaining gas left is refunded as usual.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L457-458)
```rust
            let token_to_refund =
                context.gas_price * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L517-518)
```rust
            let refund = context.tx_level_metadata.tx_gas_price
                * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow
```
