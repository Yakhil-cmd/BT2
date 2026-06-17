### Title
Unsafe `u64`-to-`i64` Cast in `compute_gas_refund` Silently Corrupts Gas Accounting — (`basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, both `native_used` and `gas_used` are `u64` values that are cast to `i64` without any bounds check. In Rust, `as`-casts between integer types are wrapping (defined behavior), so if either value exceeds `i64::MAX` the cast silently produces a negative number. This corrupts the `delta_gas` sign, causing the native-resource-to-gas adjustment to be skipped entirely, and the user receives a larger gas refund than they are entitled to.

---

### Finding Description

In `compute_gas_refund` at line 72:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};
``` [1](#0-0) 

Both operands are `u64`:

- `native_used: u64` — computed as `full_native_limit.saturating_sub(resources.native().remaining().as_u64())`, where `full_native_limit = gas_limit.saturating_mul(native_per_gas)`. It can reach `u64::MAX - 1`.
- `gas_used: u64` — computed as `gas_limit - remaining_ergs / ERGS_PER_GAS`. It is bounded by `gas_limit`. [2](#0-1) [3](#0-2) 

`i64::MAX = 9_223_372_036_854_775_807`. Any `u64` value above this threshold wraps to a negative `i64` on a Rust `as` cast.

**Scenario A — `(native_used / native_per_gas) as i64` wraps negative:**
`native_used / native_per_gas` is at most `gas_limit` (since `native_used ≤ gas_limit × native_per_gas`). If `gas_limit > i64::MAX`, the quotient exceeds `i64::MAX` and wraps to a large negative number. `delta_gas` becomes negative, the `if delta_gas > 0` guard at line 75 is never entered, and `gas_used` is **not** increased to account for the excess native consumption. The user's gas refund is inflated. [4](#0-3) 

**Scenario B — `gas_used as i64` wraps negative:**
If `gas_used > i64::MAX`, the subtraction `(native_used / native_per_gas) as i64 - (negative)` yields a large positive `delta_gas`. Line 78 then executes `gas_used += delta_gas as u64`, which can overflow `u64` (wrapping in release mode), producing a near-zero `gas_used` and a refund approaching the full `gas_limit`. [4](#0-3) 

The only guard for L2 transactions is:

```rust
require!(
    tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX,
    InvalidTransaction::CallerGasLimitTooHigh,
    system
)?;
``` [5](#0-4) 

This check only prevents `gas_limit × ERGS_PER_GAS` from overflowing `u64`; it does **not** prevent `gas_limit > i64::MAX`. The maximum allowed `gas_limit` is `u64::MAX / ERGS_PER_GAS`. If `ERGS_PER_GAS = 1`, this equals `u64::MAX − 1`, which is roughly twice `i64::MAX`, making both overflow scenarios reachable. The constant `MAX_BLOCK_GAS_LIMIT` is defined as `u64::MAX / ERGS_PER_GAS`, confirming the bound is purely a function of `ERGS_PER_GAS`. [6](#0-5) 

For L1 transactions processed via `process_l1_transaction`, the block-gas-limit check (`tx_gas_limit <= block_gas_limit`) is bypassed entirely, leaving no upper bound on `gas_limit` from the validation path. [7](#0-6) 

---

### Impact Explanation

- **Scenario A:** `delta_gas` is silently negative → the native-resource overage is ignored → `gas_used` is understated → the user receives a gas refund larger than deserved → the operator/protocol is underpaid. This is a direct resource-accounting loss.
- **Scenario B:** `gas_used` wraps near zero after the `u64` addition overflow → the user receives a refund close to the full `gas_limit` → severe protocol fund loss.

Both outcomes are state-transition / resource-accounting bugs with direct financial impact on the protocol.

---

### Likelihood Explanation

- **If `ERGS_PER_GAS ≥ 2`:** `MAX_BLOCK_GAS_LIMIT ≤ i64::MAX`, so L2 transactions cannot trigger the overflow. Likelihood is low for L2.
- **If `ERGS_PER_GAS = 1`:** `gas_limit` can reach `u64::MAX − 1 > i64::MAX`. Any L2 transaction with `gas_limit > i64::MAX` triggers the bug. Likelihood is high.
- **L1 transactions:** bypass the block-gas-limit check; an L1 sender can supply an arbitrarily large `gas_limit`. If `compute_gas_refund` is called in the L1 path (evidenced by 10 `native_per_gas` references in `process_l1_transaction.rs`), the overflow is reachable regardless of `ERGS_PER_GAS`. [8](#0-7) 

---

### Recommendation

Replace the bare `as i64` casts with checked conversions and handle the out-of-range case explicitly:

```rust
let delta_gas: i64 = if native_per_gas == 0 {
    0
} else {
    let native_gas_equiv = (native_used / native_per_gas)
        .min(i64::MAX as u64) as i64;
    let gas_used_signed = gas_used.min(i64::MAX as u64) as i64;
    native_gas_equiv.saturating_sub(gas_used_signed)
};
```

Alternatively, perform the comparison in `u64` space entirely:

```rust
let native_gas_equiv = native_used / native_per_gas;
if native_gas_equiv > gas_used {
    gas_used = native_gas_equiv; // already bounded by gas_limit
}
```

This eliminates the signed-integer domain entirely and is semantically equivalent to the intended logic.

---

### Proof of Concept

1. Craft a transaction (L1 or L2 with `ERGS_PER_GAS = 1`) with `gas_limit = i64::MAX + 1` (= `0x8000_0000_0000_0000`).
2. Execute the transaction such that all native resources are consumed (`native_used = gas_limit × native_per_gas`).
3. In `compute_gas_refund`, `native_used / native_per_gas = gas_limit = i64::MAX + 1`.
4. `(i64::MAX + 1) as i64` wraps to `i64::MIN = −9_223_372_036_854_775_808`.
5. `delta_gas = i64::MIN − (gas_used as i64)` is deeply negative.
6. The `if delta_gas > 0` guard is not entered; `gas_used` is not adjusted upward.
7. `total_gas_refund = gas_limit − gas_used` is inflated by the full native-resource overage.
8. The user receives an unearned refund; the operator is underpaid by up to `gas_limit × gas_price` tokens. [9](#0-8)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L31-33)
```rust
    let mut gas_used = gas_limit
        .checked_sub(resources.ergs().0.div_floor(ERGS_PER_GAS))
        .ok_or(internal_error!("gas remaining > gas limit"))?;
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

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-84)
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

    let total_gas_refund = gas_limit - gas_used;
    system_log!(system, "Refund after accounting for unused gas, refund counters and native cost: {total_gas_refund}\n");
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L69-73)
```rust
    require!(
        tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX,
        InvalidTransaction::CallerGasLimitTooHigh,
        system
    )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L78-95)
```rust
    if !transaction.is_service() {
        {
            // Validate that the transaction's gas limit is not larger than
            // the block's gas limit.
            let block_gas_limit = system.get_gas_limit();
            // First, check block gas limit can be represented as ergs.
            require!(
                block_gas_limit <= MAX_BLOCK_GAS_LIMIT,
                InvalidTransaction::BlockGasLimitTooHigh,
                system
            )?;
            require!(
                tx_gas_limit <= block_gas_limit,
                InvalidTransaction::CallerGasLimitMoreThanBlock,
                system
            )?;
        }
    }
```

**File:** basic_bootloader/src/bootloader/constants.rs (L39-39)
```rust
pub const MAX_BLOCK_GAS_LIMIT: u64 = u64::MAX / ERGS_PER_GAS;
```
