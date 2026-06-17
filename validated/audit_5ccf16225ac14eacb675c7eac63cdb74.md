### Title
Incorrect `as i64` Cast in `compute_gas_refund` Silently Negates `delta_gas`, Causing Incorrect Gas Refund Accounting - (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

### Summary

In `compute_gas_refund`, the `delta_gas` value is computed by casting a `u64` quotient to `i64`. When the quotient `native_used / native_per_gas` exceeds `i64::MAX`, the cast silently wraps to a negative value. The subsequent `if delta_gas > 0` guard then fails to fire even though the actual delta is large and positive, causing the extra gas charge to be skipped entirely. This is the direct analog of the reported sign-mismatch inequality bug: a value that should be treated as a large positive is compared as if it were negative, so the guard always evaluates to false in the overflow case.

### Finding Description

In `compute_gas_refund`:

```rust
// basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs, line 62-79
let full_native_limit = if cfg!(feature = "unlimited_native") || native_per_gas == 0 {
    u64::MAX - 1
} else {
    gas_limit.saturating_mul(native_per_gas)   // can saturate to u64::MAX for L1 txs
};
let native_used = full_native_limit.saturating_sub(resources.native().remaining().as_u64());

let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)  // ← unsafe cast
};

if delta_gas > 0 {
    gas_used += delta_gas as u64;
}
```

`native_used / native_per_gas` is a `u64`. When it exceeds `i64::MAX` (~9.2 × 10¹⁸), the `as i64` cast wraps to a negative value. `delta_gas` then becomes negative, the `if delta_gas > 0` guard is never entered, and `gas_used` is not increased by the native-resource-derived delta. The result is that `total_gas_refund = gas_limit - gas_used` is over-estimated, and the refund recipient receives more tokens from the treasury than they are entitled to.

The overflow condition is reachable for L1 (priority) transactions because:

1. `prepare_and_check_resources` uses **saturating** arithmetic for L1 transactions — `native_prepaid_from_gas = native_per_gas.checked_mul(gas_limit).unwrap_or(u64::MAX)` — so `full_native_limit` can saturate to `u64::MAX`.
2. With `native_per_gas = 1` (i.e., `gas_price = L1_TX_NATIVE_PRICE = 10`) and `gas_limit > i64::MAX`, `full_native_limit = gas_limit`, `native_used` can reach `gas_limit`, and `native_used / 1 = native_used > i64::MAX`, causing the cast to wrap negative.
3. L1 transactions bypass the block-level gas-limit check that would otherwise cap `gas_limit` at `MAX_TX_GAS_LIMIT = u64::MAX / 256 ≈ 7.2 × 10¹⁶` (which is itself below `i64::MAX`). However, the code explicitly acknowledges that L1 validation may be wrong and uses saturating fallbacks throughout.

Additionally, when `native_per_gas * gas_limit` saturates to `u64::MAX` (e.g., `native_per_gas = 2`, `gas_limit = u64::MAX/2 + 1`), `native_used` can reach `u64::MAX`, and `u64::MAX / 2 > i64::MAX`, triggering the same overflow.

### Impact Explanation

When the cast overflows, `delta_gas` is negative, the guard `if delta_gas > 0` is never entered, and `gas_used` is not adjusted upward to account for native resource consumption. Consequently:

- `total_gas_refund = gas_limit - gas_used` is larger than it should be.
- The excess refund is paid from the treasury (`BASE_TOKEN_HOLDER_ADDRESS`) to the refund recipient.
- The operator receives less fee than the actual native resource consumption warrants.

This constitutes a resource accounting bug leading to incorrect token distribution from the treasury — a public-funds-loss path for the protocol treasury.

### Likelihood Explanation

The overflow requires `native_used / native_per_gas > i64::MAX`. For the `native_per_gas = 1` path this demands `gas_limit > i64::MAX ≈ 9.2 × 10¹⁸`, which is far beyond any realistic L1 transaction gas limit. For the saturating-overflow path (`native_per_gas * gas_limit` wraps), it requires `gas_limit > u64::MAX / (2 * native_per_gas)`, again requiring an astronomically large gas limit. In practice, L1 transactions carry gas limits in the millions to tens of millions. The likelihood is therefore very low under normal operating conditions, but the code path is reachable in principle because L1 transactions bypass the block-level gas-limit cap and the code explicitly uses saturating fallbacks.

### Recommendation

Replace the unsafe `as i64` cast with a checked comparison that avoids signed arithmetic entirely:

```rust
// Safe: both operands are u64; compare before subtracting
let native_gas_equiv = native_used / native_per_gas;
if native_gas_equiv > gas_used {
    // saturating_sub is safe here since native_gas_equiv > gas_used
    let delta = native_gas_equiv - gas_used;
    gas_used = gas_used.saturating_add(delta);
}
```

This eliminates the `i64` cast entirely and correctly handles all `u64` magnitudes without wrapping.

### Proof of Concept

1. Submit an L1 priority transaction with:
   - `gas_price = 10` (equal to `L1_TX_NATIVE_PRICE`)
   - `gas_limit = u64::MAX / 2 + 1` (so `native_per_gas = 1`, `full_native_limit = gas_limit > i64::MAX`)
   - Calldata that exhausts all native resources during execution
2. In `compute_gas_refund`:
   - `full_native_limit = gas_limit` (no saturation since `native_per_gas = 1`)
   - `native_used ≈ gas_limit > i64::MAX`
   - `(native_used / 1) as i64` wraps to a large negative value
   - `delta_gas < 0`, guard fails, `gas_used` is not increased
   - `total_gas_refund = gas_limit - gas_used` is vastly over-estimated
3. The refund recipient receives treasury tokens far in excess of what the actual gas consumption warrants.

**Relevant code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L59-80)
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L490-496)
```rust
    let native_prepaid_from_gas = native_per_gas.checked_mul(gas_limit)
        .unwrap_or_else(|| {
            system_log!(
                system,
                "Native prepaid from gas calculation for L1 tx overflows, using saturated arithmetic instead");
                u64::MAX
        });
```

**File:** basic_bootloader/src/bootloader/constants.rs (L64-70)
```rust
// Default native price for L1->L2 transactions.
// TODO (EVM-1157): find a reasonable value for it.
pub const L1_TX_NATIVE_PRICE: U256 = U256::from_limbs([10, 0, 0, 0]);

// Upgrade, service and gateway mailbox transactions are expected to have ~72 million gas. We will use enough
// gas to ensure that multiplied by the 72 million they exceed the native computational limit.
pub const FREE_L1_TX_NATIVE_PER_GAS: u64 = 10000;
```
