### Title
Asymmetric `delta_gas` Adjustment Overcharges Users When Native Resource Consumption Is Lower Than EVM Gas Consumption - (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, the `delta_gas` reconciliation between native resource consumption and EVM gas consumption is applied **only in one direction**: when native consumption exceeds gas consumption (`delta_gas > 0`), extra gas is charged to the user. However, when gas consumption exceeds native consumption (`delta_gas < 0`), no corresponding reduction of `gas_used` is applied. This means users are systematically overcharged whenever their EVM gas consumption is higher than what the native resource model implies, and the operator receives more fees than the actual proving cost warrants.

---

### Finding Description

ZKsync OS implements a double resource accounting model: EVM gas (ergs) and native resource (proving cost). At the end of a transaction, `compute_gas_refund` reconciles the two by computing:

```
delta_gas = (native_used / native_per_gas) as i64 - (gas_used as i64)
```

The intent is to ensure that if native resource consumption implies more gas was used than the EVM gas counter shows, the user is charged for the difference. This is documented in `docs/double_resource_accounting.md`:

> If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs.

However, the code only handles the positive case:

```rust
if delta_gas > 0 {
    // In this case, the native resource consumption is more than the
    // gas consumption accounted for. Consume extra gas.
    gas_used += delta_gas as u64;
}
// TODO: return delta_gas to gas_used?
```

The `// TODO: return delta_gas to gas_used?` comment on line 80 explicitly acknowledges the missing negative case. When `delta_gas < 0` (i.e., `native_used / native_per_gas < gas_used`), the user has consumed more EVM gas than the native resource model implies, but `gas_used` is **not reduced**. The user is charged for the full EVM gas used, while the native resource cost was lower. This is an asymmetric treatment: the system always adjusts upward but never downward.

The root cause is in `compute_gas_refund` at lines 69–81:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};

if delta_gas > 0 {
    gas_used += delta_gas as u64;
}
// TODO: return delta_gas to gas_used?
```

The missing branch would be:
```rust
else if delta_gas < 0 {
    gas_used = gas_used.saturating_sub((-delta_gas) as u64);
}
```

---

### Impact Explanation

**Impact: Medium**

When a transaction's EVM gas consumption is higher than what the native resource model implies (i.e., the transaction is computationally cheap to prove but uses many EVM gas units — e.g., heavy SLOAD/SSTORE operations that are cheap in native but expensive in EVM gas), the user is overcharged. The excess fee flows to the operator/coinbase. This is a direct, quantifiable financial loss for users: they pay more than the actual proving cost of their transaction warrants.

The magnitude of overcharge per transaction is bounded by `|delta_gas| * gas_price`, which can be significant for transactions with high EVM gas usage but low native resource consumption.

---

### Likelihood Explanation

**Likelihood: High**

The condition `delta_gas < 0` occurs whenever `native_used / native_per_gas < gas_used`. This is a common scenario: many EVM operations (e.g., SLOAD, SSTORE, CALL) are expensive in EVM gas but relatively cheap in native (proving) resource. Any transaction that uses a high `gas_price` (increasing `native_per_gas`) relative to its actual native consumption will trigger this path. The `// TODO` comment in the code confirms the developers are aware this case is unhandled.

---

### Recommendation

In `compute_gas_refund`, handle the negative `delta_gas` case symmetrically:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else if delta_gas < 0 {
    // Native consumption implies less gas was used than EVM gas counter shows.
    // Reduce gas_used to avoid overcharging the user.
    gas_used = gas_used.saturating_sub((-delta_gas) as u64);
    // Ensure we never go below minimal_gas_used
    gas_used = core::cmp::max(gas_used, minimal_gas_used);
}
```

Also update `docs/double_resource_accounting.md` to document the symmetric behavior.

---

### Proof of Concept

The asymmetry is directly visible in the production code and acknowledged by the `// TODO` comment: [1](#0-0) 

The documentation only describes the positive case: [2](#0-1) 

**Concrete scenario:**

- `gas_limit = 100_000`, `native_per_gas = 1000`
- Transaction uses `gas_used = 50_000` EVM gas (ergs path)
- Transaction uses `native_used = 20_000_000` native units
- `native_used / native_per_gas = 20_000` (implied gas from native)
- `delta_gas = 20_000 - 50_000 = -30_000` (negative)
- Current code: `gas_used` stays at `50_000`, user is charged for 50,000 gas
- Correct behavior: `gas_used` should be reduced to `20_000`, user charged for 20,000 gas
- Overcharge: `30,000 * gas_price` tokens extracted from user and given to operator

The `refund_and_commit_fee` function in both the ZK and Ethereum transaction flows uses `gas_used` directly to compute the operator payment and user refund: [3](#0-2) [4](#0-3)

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

**File:** docs/double_resource_accounting.md (L47-51)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L514-516)
```rust
        let token_to_pay_operator = U256::from(context.gas_used)
            .checked_mul(gas_price_for_operator)
            .ok_or(internal_error!("gu*gpfo"))?;
```
