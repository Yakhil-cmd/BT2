### Title
Signed Integer Narrowing Cast in `compute_gas_refund` Silently Corrupts `delta_gas` for L1 Transactions with Large Gas Limits - (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, the expression `(native_used / native_per_gas) as i64` performs an unchecked narrowing cast from `u64` to `i64`. When `native_used / native_per_gas` exceeds `i64::MAX` (~9.2 × 10¹⁸), Rust's `as` cast silently wraps the value to a large negative number. This makes `delta_gas` incorrectly negative, suppressing the upward adjustment of `gas_used` that is supposed to compensate for native resource consumption exceeding EVM gas consumption. The result is a resource accounting error: the user receives a larger gas refund than they are entitled to, and the operator is underpaid.

---

### Finding Description

In `compute_gas_refund`, the `delta_gas` calculation is:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};

if delta_gas > 0 {
    gas_used += delta_gas as u64;
}
``` [1](#0-0) 

Both `native_used` and `native_per_gas` are `u64`. The division `native_used / native_per_gas` is also `u64`. The `as i64` cast is a **wrapping** (not checked) cast in Rust. When the quotient exceeds `i64::MAX = 9_223_372_036_854_775_807`, the cast wraps to a large negative value.

The `delta_gas` variable is then negative, the `if delta_gas > 0` guard fires false, and `gas_used` is **not** adjusted upward. The system then computes:

```rust
let total_gas_refund = gas_limit - gas_used;
``` [2](#0-1) 

Because `gas_used` is smaller than it should be, `total_gas_refund` is larger than it should be, and the user receives an inflated refund.

**Why `native_used / native_per_gas` can exceed `i64::MAX`:**

For **L2 transactions**, the validation at line 70 of `validation_impl.rs` enforces:

```rust
require!(
    tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX,
    InvalidTransaction::CallerGasLimitTooHigh,
    ...
)?;
``` [3](#0-2) 

With `ERGS_PER_GAS = 256`, this bounds `gas_limit < u64::MAX / 256 ≈ 7.2 × 10¹⁶`, which is well below `i64::MAX`. So L2 transactions are **not** affected.

For **L1 transactions**, no such upper bound is enforced on `gas_limit`. The bootloader explicitly handles L1 edge cases with saturating arithmetic and logs, but does **not** bound `gas_limit`:

```rust
fn prepare_and_check_resources<...>(
    ...
    gas_limit: u64,
    gas_price: U256,
    ...
) -> Result<ResourceAndFeeInfo<S>, BootloaderSubsystemError>
``` [4](#0-3) 

An L1 transaction with `gas_limit > i64::MAX` and `native_per_gas = 1` (i.e., `gas_price = L1_TX_NATIVE_PRICE = 10`) produces:

- `full_native_limit = gas_limit * 1 = gas_limit`
- `native_used ≈ gas_limit` (if all native is consumed)
- `native_used / native_per_gas ≈ gas_limit > i64::MAX`
- `(gas_limit) as i64` → wraps to a large negative number
- `delta_gas` → large negative → guard suppresses adjustment
- `gas_used` stays at its EVM-only value (e.g., 21,000)
- `total_gas_refund = gas_limit - 21_000 ≈ gas_limit`

The operator receives `21_000 * gas_price` instead of `gas_limit * gas_price`.

---

### Impact Explanation

The operator is underpaid by `(gas_limit - gas_used_evm) * gas_price` tokens. For an L1 transaction with `gas_limit = 2^63 + 100` and `gas_price = 10`, the operator loses approximately `2^63 * 10` native tokens. The user's deposit is fully consumed (deposit = operator fee + refund), but the split is wrong: the user receives a refund proportional to `gas_limit - 21_000` instead of the correct `gas_limit - correct_gas_used`. This is a direct financial loss to the operator/protocol.

---

### Likelihood Explanation

L1 transactions are submitted by unprivileged users through L1 bridge contracts. The bootloader explicitly acknowledges that L1 contract validation may be incomplete or stale:

> "Note that the 'validation errors' are practically unreachable, as gas_limit, gas_price and gas_per_pubdata are either checked or set by the L1 contracts. We decide to handle these cases as a fallback in case the L1 contracts aren't properly updated." [5](#0-4) 

If L1 contracts do not enforce `gas_limit ≤ i64::MAX`, any user can submit a crafted L1 transaction to trigger this path. The `native_per_gas` value of 1 is achievable when `gas_price = L1_TX_NATIVE_PRICE = 10`.

---

### Recommendation

Replace the unchecked `as i64` cast with a checked or saturating alternative. The correct approach is to compute `delta_gas` using `u64` arithmetic and only convert to signed at the end:

```rust
let native_gas_equivalent = native_used / native_per_gas;
let delta_gas: i64 = if native_gas_equivalent > gas_used {
    // native_gas_equivalent - gas_used is guaranteed to fit in i64
    // because both are bounded by gas_limit which is bounded by i64::MAX
    // after adding the missing gas_limit upper bound check for L1 txs.
    (native_gas_equivalent - gas_used) as i64
} else {
    -((gas_used - native_gas_equivalent) as i64)
};
```

Additionally, add an explicit upper bound check on `gas_limit` for L1 transactions (analogous to the L2 check), or use `i128` for the intermediate computation to avoid wrapping entirely.

---

### Proof of Concept

Concrete values triggering the bug:

- `gas_limit = 9_223_372_036_854_775_810` (= `i64::MAX + 3`, valid `u64`)
- `native_per_gas = 1` (achieved when `gas_price = 10 = L1_TX_NATIVE_PRICE`)
- `gas_used = 21_000` (minimal EVM gas, e.g., simple ETH transfer)
- `native_used = 9_223_372_036_854_775_810` (all native consumed)

Step-by-step:

```
native_used / native_per_gas = 9_223_372_036_854_775_810  // u64
(9_223_372_036_854_775_810_u64) as i64 = i64::MIN + 2 = -9_223_372_036_854_775_806
gas_used as i64 = 21_000
delta_gas = -9_223_372_036_854_775_806 - 21_000 = very negative
if delta_gas > 0  →  false  →  gas_used stays at 21_000

total_gas_refund = 9_223_372_036_854_775_810 - 21_000 = 9_223_372_036_854_754_810
```

Operator receives `21_000 * 10 = 210_000` native tokens instead of the correct `9_223_372_036_854_775_810 * 10` tokens. The user's deposit is refunded almost entirely. [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L66-83)
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

    let total_gas_refund = gas_limit - gas_used;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L69-73)
```rust
    require!(
        tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX,
        InvalidTransaction::CallerGasLimitTooHigh,
        system
    )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L422-433)
```rust
///
/// Compute and perform some checks on fee/resource parameters.
/// This function handles cases that for L2 transactions would be
/// validation errors, as "invalidating" an L1 transaction can halt
/// the chain (due to the priority queue).
/// Note that the "validation errors" are practically unreachable, as
/// gas_limit, gas_price and gas_per_pubdata are either checked or set
/// by the L1 contracts. We decide to handle these cases as a fallback in
/// case the L1 contracts aren't properly updated to reflect a change in
/// ZKsync OS.
/// The approach is to use saturating arithmetic and emit a system
/// log if this situation ever happens.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L435-447)
```rust
fn prepare_and_check_resources<
    'a,
    S: EthereumLikeTypes + 'a,
    Config: BasicBootloaderExecutionConfig,
>(
    system: &mut System<S>,
    transaction: &AbiEncodedTransaction<S::Allocator>,
    is_priority_op: bool,
    gas_limit: u64,
    gas_price: U256,
    gas_per_pubdata: u32,
    intrinsic_pubdata: u64,
) -> Result<ResourceAndFeeInfo<S>, BootloaderSubsystemError>
```
