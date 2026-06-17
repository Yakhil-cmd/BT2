### Title
Integer Division Truncation in `delta_gas` Calculation Causes Systematic Undercharging of Transaction Fees - (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, the `delta_gas` adjustment that reconciles native resource consumption with EVM gas consumption performs integer division before the result is used to scale by `gas_price`. The truncation causes every transaction whose native consumption is not an exact multiple of `native_per_gas` to be undercharged by up to 1 gas unit, systematically underpaying the operator.

---

### Finding Description

In `refund_calculation.rs`, the function `compute_gas_refund` computes how much additional gas a user must pay to cover native (proving) resource consumption that exceeds their EVM gas consumption:

```rust
// Line 69-73
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};

if delta_gas > 0 {
    gas_used += delta_gas as u64;
}
``` [1](#0-0) 

The expression `native_used / native_per_gas` is integer (floor) division. When `native_used` is not exactly divisible by `native_per_gas`, the fractional part is silently discarded. The result `delta_gas` is then added to `gas_used`, and `gas_used` is subsequently multiplied by `gas_price` to compute the fee charged to the user and the refund returned:

```rust
// Line 83
let total_gas_refund = gas_limit - gas_used;
``` [2](#0-1) 

The full fee path is:

```
fee_paid = gas_price × gas_used
         = gas_price × floor(native_used / native_per_gas)   [when delta_gas > 0]
```

The correct charge to fully cover native resource consumption should be:

```
fee_paid_correct = gas_price × ceil(native_used / native_per_gas)
```

The difference is `gas_price × 1` wei at most — i.e., up to one full gas unit of fee is silently dropped per transaction.

The `native_per_gas` value itself is computed with `div_ceil` (rounding up) in `validation_impl.rs`:

```rust
// Line 135
u256_try_to_u64(&gas_price.div_ceil(native_price))
``` [3](#0-2) 

This means `native_per_gas` is already rounded up, making it more likely that `native_used % native_per_gas != 0` for most transactions, triggering the truncation on every such transaction.

The documentation explicitly describes the intended formula as:

> `deltaGas := (nativeUsed / nativePerGas) - gasUsed` [4](#0-3) 

However, the spec does not clarify whether floor or ceiling division is intended. Using floor division systematically favors the user over the operator.

---

### Impact Explanation

- **Type**: Resource accounting bug — systematic undercharge of transaction fees.
- **Who loses**: The block operator/coinbase receives up to 1 gas unit less per transaction than the native resource consumption warrants.
- **Who benefits**: Every transaction sender whose `native_used % native_per_gas != 0` pays slightly less than they should.
- **Magnitude**: At most `gas_price` wei per transaction (1 gas unit). At high gas prices (e.g., 100 gwei), this is 100 gwei per transaction. Across millions of transactions, the cumulative operator loss is non-trivial.
- **Scope match**: This is a public-funds-loss path (operator fee shortfall) triggered by any unprivileged transaction sender.

---

### Likelihood Explanation

- **High**. The condition `native_used % native_per_gas != 0` holds for virtually every real transaction, since `native_used` is the sum of many heterogeneous native costs (EVM opcodes, pubdata, bootloader overhead) and `native_per_gas` is an arbitrary ratio derived from `gas_price / native_price`. There is no mechanism that would cause these to align exactly.
- Any user submitting a standard EVM transaction triggers this path through `compute_gas_refund`.

---

### Recommendation

Replace the floor division with ceiling division in the `delta_gas` calculation to ensure the user is charged for the full native resource consumption:

```rust
// Before (truncates):
(native_used / native_per_gas) as i64 - (gas_used as i64)

// After (rounds up, fully covers native cost):
native_used.div_ceil(native_per_gas) as i64 - (gas_used as i64)
```

This matches the pattern already used when computing `native_per_gas` itself (`gas_price.div_ceil(native_price)`), making the rounding direction consistent throughout the fee pipeline.

---

### Proof of Concept

**Setup**:
- `native_price = 7` (operator-set)
- `gas_price = 14` → `native_per_gas = ceil(14/7) = 2`
- Transaction uses `native_used = 101` native units, `gas_used = 50` EVM gas

**Current behavior** (floor division):
```
delta_gas = floor(101 / 2) - 50 = 50 - 50 = 0
gas_used stays at 50
fee = gas_price × 50 = 14 × 50 = 700 wei
```

**Correct behavior** (ceiling division):
```
delta_gas = ceil(101 / 2) - 50 = 51 - 50 = 1
gas_used becomes 51
fee = gas_price × 51 = 14 × 51 = 714 wei
```

The operator is shortchanged by 14 wei (1 gas unit × gas_price) on this single transaction. With `native_used = 101` and `native_per_gas = 2`, the user consumed native resources equivalent to 50.5 gas units but only pays for 50. The 0.5-unit remainder is silently absorbed by the operator. [5](#0-4)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L59-84)
```rust
    let full_native_limit = if cfg!(feature = "unlimited_native") || native_per_gas == 0 {
        u64::MAX - 1
    } else {
        gas_limit.saturating_mul(native_per_gas)
    };
    let native_used = full_native_limit.saturating_sub(resources.native().remaining().as_u64());

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

    let total_gas_refund = gas_limit - gas_used;
    system_log!(system, "Refund after accounting for unused gas, refund counters and native cost: {total_gas_refund}\n");
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L135-137)
```rust
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
```

**File:** docs/double_resource_accounting.md (L48-50)
```markdown
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.
```
