### Title
Signed Integer Cast Overflow in `compute_gas_refund` Causes Native Resource Undercharging - (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, the expression `(native_used / native_per_gas) as i64` casts a `u64` quotient to `i64` without bounds checking. When the quotient exceeds `i64::MAX` (≈ 9.2 × 10¹⁸), Rust's wrapping cast produces a large negative `i64`. The subsequent `if delta_gas > 0` guard then silently skips the extra-gas charge that is supposed to compensate the operator for native resource consumption, causing the transaction sender to receive a larger-than-deserved refund while the operator is underpaid.

---

### Finding Description

Inside `compute_gas_refund`, the `#[cfg(not(feature = "unlimited_native"))]` block computes a signed delta to reconcile EVM gas used with native resource consumption:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)  // ← line 72
};

if delta_gas > 0 {
    gas_used += delta_gas as u64;   // ← line 78
}
```

`native_used` and `native_per_gas` are both `u64`. The quotient `native_used / native_per_gas` is also `u64` and can be as large as `gas_limit` (because `native_used ≤ gas_limit * native_per_gas`). When `gas_limit > i64::MAX` (a value a transaction sender can freely set, since `gas_limit` is a `u64` field with no enforced upper bound at this layer), the quotient exceeds `i64::MAX`, and the `as i64` cast wraps to a large negative number. `delta_gas` therefore becomes negative, the guard `if delta_gas > 0` is false, and `gas_used` is never incremented by the native-resource-derived extra gas. The final refund `gas_limit - gas_used` is consequently larger than it should be. [1](#0-0) 

The `full_native_limit` is computed as `gas_limit.saturating_mul(native_per_gas)`, so `native_used` is bounded by `gas_limit * native_per_gas`, confirming that `native_used / native_per_gas ≤ gas_limit`. The overflow therefore requires only `gas_limit > i64::MAX`. [2](#0-1) 

The downstream refund and operator-payment paths consume the (now-incorrect) `gas_used` value directly: [3](#0-2) [4](#0-3) 

---

### Impact Explanation

The `delta_gas` mechanism exists precisely to ensure that when native resource consumption (proving cycles, pubdata) exceeds what EVM gas alone would charge, the difference is billed to the sender. Bypassing it means:

1. The sender receives a token refund larger than warranted — they pay for `gas_limit` gas upfront but are refunded as if they used fewer gas units than the native resource cost demands.
2. The operator is underpaid by `delta_gas_correct * gas_price` tokens for the native resources actually consumed.
3. The attacker effectively obtains native proving resources (which have real off-chain cost) at a discount or for free beyond the gas they are charged.

This is a **resource accounting bug** with direct financial impact: operator revenue is reduced and the protocol's cost model is violated.

---

### Likelihood Explanation

- `gas_limit` is a `u64` field set freely by the transaction sender; no enforced cap at `i64::MAX` is present in the bootloader validation layer examined.
- The condition requires `gas_limit > i64::MAX` (≈ 9.2 × 10¹⁸). The sender must pre-pay `gas_limit * gas_price` tokens, so a very large gas limit requires a very large balance. However, with `native_per_gas = 1` (achieved when `gas_price ≈ native_price`), the required balance equals `gas_limit`, and the attacker recovers most of it as refund — the net cost is only the legitimately consumed EVM gas, while native resources are undercharged.
- The `#[cfg(not(feature = "unlimited_native"))]` guard confirms this path is active in production builds. [5](#0-4) 

---

### Recommendation

Replace the unchecked `as i64` cast with a saturating or checked conversion:

```rust
let native_gas_equivalent = (native_used / native_per_gas).min(i64::MAX as u64) as i64;
let delta_gas = native_gas_equivalent - (gas_used as i64);
```

Alternatively, keep the arithmetic in `u64` and compare directly:

```rust
let native_gas_equivalent = native_used / native_per_gas;
if native_gas_equivalent > gas_used {
    let delta = native_gas_equivalent - gas_used;
    gas_used = gas_used.saturating_add(delta);
}
```

Additionally, enforce an upper bound on `gas_limit` (e.g., `≤ i64::MAX`) during transaction validation to prevent the entire class of signed/unsigned cast issues in this function.

---

### Proof of Concept

**Setup:**
- `native_per_gas = 1` (achieved by setting `gas_price = native_price`)
- `gas_limit = u64::MAX` (or any value > `i64::MAX`)
- Sender has sufficient balance to pre-pay `gas_limit * gas_price`

**Execution trace in `compute_gas_refund`:**

1. `full_native_limit = gas_limit.saturating_mul(1) = gas_limit = u64::MAX`
2. Transaction consumes all native resources: `native_used = u64::MAX`
3. `native_used / native_per_gas = u64::MAX`
4. `(u64::MAX) as i64 = -1` ← wrapping cast overflow
5. `delta_gas = -1 - (gas_used as i64)` → large negative value
6. `if delta_gas > 0` → **false**, extra gas not charged
7. `gas_used` remains at its pre-delta value (e.g., `gas_used_evm`)
8. `total_gas_refund = gas_limit - gas_used_evm` → attacker receives a refund that does not account for the native resource cost
9. Operator receives only `gas_used_evm * gas_price` instead of the correct `(gas_used_evm + delta_gas_correct) * gas_price` [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L59-64)
```rust
    let full_native_limit = if cfg!(feature = "unlimited_native") || native_per_gas == 0 {
        u64::MAX - 1
    } else {
        gas_limit.saturating_mul(native_per_gas)
    };
    let native_used = full_native_limit.saturating_sub(resources.native().remaining().as_u64());
```

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

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L83-89)
```rust
    let total_gas_refund = gas_limit - gas_used;
    system_log!(system, "Refund after accounting for unused gas, refund counters and native cost: {total_gas_refund}\n");
    require_internal!(
        total_gas_refund <= gas_limit,
        "Gas refund greater than gas limit",
        system
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
