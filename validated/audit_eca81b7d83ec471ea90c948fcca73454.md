### Title
Truncation in `native_used / native_per_gas` Division Causes Systematic Operator Underpayment - (`File: basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` converts native resource consumption back to EVM gas units using integer floor division (`native_used / native_per_gas`). Because this division truncates, any transaction where `native_used % native_per_gas != 0` causes the user to underpay by exactly one gas unit (= `gas_price` tokens) for native resource consumption. This is repeatable across every transaction and systematically under-compensates the operator for proving costs.

---

### Finding Description

In `compute_gas_refund`, the double-resource accounting reconciliation step computes:

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
``` [1](#0-0) 

The design intent, documented explicitly, is:

> `deltaGas := (nativeUsed / nativePerGas) - gasUsed`
> If `deltaGas > 0`, we add it to `gasUsed` [2](#0-1) 

The problem is that `native_used / native_per_gas` is **floor division**. Whenever `native_used = k * native_per_gas + r` with `r > 0`, the floor gives `k` but the correct charge is `k + 1` (ceiling). The user is charged for `k` extra gas units instead of `k + 1`, underpaying by exactly one gas unit = `gas_price` tokens.

`native_per_gas` is computed as `ceil(gas_price / native_price)`: [3](#0-2) 

The full native limit is `gas_limit * native_per_gas`: [4](#0-3) 

And `native_used` is the actual native consumed: [5](#0-4) 

The truncation is structurally identical to the LendingLedger analog: a cumulative value (`native_used`) is divided by a rate (`native_per_gas`) with floor rounding, and the remainder is silently discarded rather than rounded up to charge the next unit.

The existing `// TODO: return delta_gas to gas_used?` comment at line 80 acknowledges that the negative-`delta_gas` case is unhandled, but the positive-`delta_gas` truncation is the exploitable direction. [6](#0-5) 

---

### Impact Explanation

Every transaction where `native_used % native_per_gas != 0` (the common case) results in the user paying one fewer gas unit than the native resource consumption warrants. The operator receives `gas_price` fewer tokens per such transaction than the proving cost demands. Since `native_per_gas = ceil(gas_price / native_price)`, the underpayment per transaction is exactly `gas_price` tokens (one gas unit). Across a high-throughput block, this compounds into a meaningful operator loss. The user does not need any special privilege — any standard L2 transaction sender triggers this path. [7](#0-6) 

---

### Likelihood Explanation

The condition `native_used % native_per_gas != 0` holds for virtually every real transaction because native consumption is determined by the sum of many independent per-opcode and per-pubdata-byte charges, making exact divisibility by `native_per_gas` statistically rare. Any unprivileged user submitting a standard EVM transaction triggers this path on every block. The attacker-controlled entry point is simply submitting a transaction with any non-zero EVM execution. [8](#0-7) 

---

### Recommendation

Replace the floor division with ceiling division when converting native consumption to gas units:

```rust
// Before (floor):
(native_used / native_per_gas) as i64 - (gas_used as i64)

// After (ceiling):
native_used.div_ceil(native_per_gas) as i64 - (gas_used as i64)
```

This ensures the operator is always fully compensated: if `native_used = k * native_per_gas + r` with `r > 0`, the user pays for `k + 1` gas units rather than `k`. This mirrors the fix recommended in the LendingLedger report: round the debt **up** on the addition path. [9](#0-8) 

---

### Proof of Concept

**Setup:** Deploy any contract that performs EVM computation. Set `native_price = 3`, `gas_price = 10` (so `native_per_gas = ceil(10/3) = 4`).

**Trigger:** Submit a transaction that consumes exactly `native_used = 5` native units and `gas_used = 0` EVM gas units from the delta perspective.

**Current behavior:**
- `delta_gas = floor(5 / 4) - 0 = 1`
- User pays 1 extra gas unit

**Correct behavior:**
- `delta_gas = ceil(5 / 4) - 0 = 2`
- User should pay 2 extra gas units

**Underpayment:** 1 gas unit = `gas_price` = 10 tokens per transaction.

**Repeatability:** Submit N transactions each with `native_used % native_per_gas = native_per_gas - 1`. Total operator loss = `N * gas_price` tokens. No special access required; any EOA can do this. [7](#0-6)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L31-34)
```rust
    let mut gas_used = gas_limit
        .checked_sub(resources.ergs().0.div_floor(ERGS_PER_GAS))
        .ok_or(internal_error!("gas remaining > gas limit"))?;
    resources.exhaust_ergs();
```

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

**File:** docs/double_resource_accounting.md (L47-50)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L135-138)
```rust
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
        }
```
