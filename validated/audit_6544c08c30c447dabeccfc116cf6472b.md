### Title
Unsafe `u64`→`i64` Cast in `compute_gas_refund` Enables Gas-Accounting Corruption for L1 Transactions with Extreme Gas Limits — (File: `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` casts two `u64` values (`native_used / native_per_gas` and `gas_used`) directly to `i64` without range validation. For L2 transactions the existing `tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX` guard keeps both values below `i64::MAX`. L1 transactions have **no equivalent guard**, so a caller who submits an L1 transaction with `gas_limit > i64::MAX + MAX_BLOCK_GAS_LIMIT` causes both casts to wrap, corrupting the `delta_gas` computation and producing a `gas_used` of 0 — meaning the operator is paid nothing for the transaction.

---

### Finding Description

In `compute_gas_refund` the `deltaGas` adjustment is computed as:

```rust
// basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs  line 72
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)   // ← unsafe casts
};
```

`gas_used` and `native_used / native_per_gas` are both `u64`. Rust's `as i64` cast is a **bit-reinterpretation** (wrapping); any value above `i64::MAX ≈ 9.22 × 10¹⁸` silently becomes a large negative number.

For L2 transactions both ZK and Ethereum validation paths enforce:

```rust
// basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs  line 69-73
require!(
    tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX,
    InvalidTransaction::CallerGasLimitTooHigh, system
)?;
```

This bounds `gas_limit ≤ MAX_BLOCK_GAS_LIMIT = u64::MAX / 256 ≈ 7.2 × 10¹⁶`, well below `i64::MAX`. The casts are therefore safe for L2 paths.

L1 transactions are processed through `process_l1_transaction` and `create_resources_for_tx::<S, L1ResourcesPolicy>`. **No analogous upper-bound check exists for L1 `gas_limit`**. The `L1ResourcesPolicy` only saturates arithmetic errors; it never rejects a transaction for having an oversized gas limit. The comment on line 405 of `gas_helpers.rs` ("we checked at the very start that gas_limit * ERGS_PER_GAS doesn't overflow") refers to the L2 check and does **not** apply to the L1 code path.

Concrete arithmetic for `gas_limit = u64::MAX`, `native_per_gas = 1`, `native_used = 0`:

| Step | Value |
|---|---|
| `ergs` after `saturating_mul(256)` | `u64::MAX` |
| `resources.ergs().0.div_floor(256)` | `MAX_BLOCK_GAS_LIMIT = 72057594037927935` |
| `gas_used = u64::MAX − MAX_BLOCK_GAS_LIMIT` | `18374686479671623680` (> `i64::MAX`) |
| `gas_used as i64` | `−72057594037927936` (wraps) |
| `delta_gas = 0 − (−72057594037927936)` | `+72057594037927936` |
| `gas_used += 72057594037927936` | `18374686479671623680 + 72057594037927936 = 2⁶⁴ ≡ 0` (u64 wrap) |
| `total_gas_refund = gas_limit − 0` | `u64::MAX` |
| `require_internal!(u64::MAX ≤ u64::MAX)` | passes |
| **Returned `gas_used`** | **0** |

The operator is paid `gas_used × gas_price = 0`. The user's entire L1 deposit is refunded.

With different `native_used` values the wrapped `gas_used` can exceed `gas_limit`, causing `gas_limit − gas_used` to underflow, which triggers `require_internal!` and returns an `InternalError` — aborting block processing entirely.

---

### Impact Explanation

Two distinct outcomes depending on `native_used`:

1. **Operator fee theft / zero-fee execution**: `gas_used` wraps to 0; the operator receives no fee for processing the L1 transaction. The user's full deposit is refunded. This is a direct financial loss for the operator.

2. **Block-level DoS**: `gas_used` wraps to a value exceeding `gas_limit`; `gas_limit − gas_used` underflows; `require_internal!` fires an `InternalError`; the entire block fails. Because L1 transactions cannot be invalidated, a single crafted L1 transaction can halt block production.

Both outcomes are resource-accounting bugs with protocol-level impact, matching the Immunefi scope for state-transition / resource-accounting bugs.

---

### Likelihood Explanation

- L1 transactions bypass the `CallerGasLimitMoreThanBlock` and `CallerGasLimitTooHigh` checks that protect L2 paths.
- The `gas_limit` field in an L1 transaction is a `u64` set by the submitter on L1. If the L1 bridge contract does not enforce a ceiling below `i64::MAX + MAX_BLOCK_GAS_LIMIT ≈ 9.3 × 10¹⁸`, an attacker can trigger this path.
- The attacker must pay L1 gas to submit the transaction, but the L1 gas cost of submitting a transaction with a large `gas_limit` field is not proportional to the `gas_limit` value itself — it is determined by calldata size.
- Likelihood is **low-to-medium**: requires knowledge of the missing bound and willingness to pay L1 submission cost, but no privileged access.

---

### Recommendation

Replace the bare `as i64` casts with checked conversions that return an `InternalError` on overflow, mirroring the pattern already used elsewhere in the codebase:

```rust
// Proposed fix
let native_gas_equiv = i64::try_from(native_used / native_per_gas)
    .map_err(|_| internal_error!("native_used/native_per_gas overflows i64"))?;
let gas_used_signed = i64::try_from(gas_used)
    .map_err(|_| internal_error!("gas_used overflows i64"))?;
let delta_gas = native_gas_equiv - gas_used_signed;
```

Additionally, add an explicit upper-bound check for L1 transaction `gas_limit` analogous to the L2 check:

```rust
// In L1 transaction processing
if gas_limit > MAX_BLOCK_GAS_LIMIT {
    // saturate or log; L1 txs cannot be rejected, so saturate
    gas_limit = MAX_BLOCK_GAS_LIMIT;
}
```

---

### Proof of Concept

**Entry path**: Submit an L1→L2 priority transaction (via the ZKsync bridge on L1) with `gas_limit = u64::MAX` (or any value > `i64::MAX + MAX_BLOCK_GAS_LIMIT ≈ 9.3 × 10¹⁸`).

**Execution trace**:

1. L1 transaction enters `process_l1_transaction` — no gas-limit upper-bound check.
2. `create_resources_for_tx::<S, L1ResourcesPolicy>` is called; `ergs = gas_limit_for_tx.saturating_mul(ERGS_PER_GAS) = u64::MAX`.
3. Transaction executes; remaining ergs = `u64::MAX` (nothing spent).
4. `compute_gas_refund` is called with `gas_limit = u64::MAX`, `native_per_gas = 1`.
5. `gas_used = u64::MAX − MAX_BLOCK_GAS_LIMIT = 18374686479671623680`.
6. Line 72: `gas_used as i64 = −72057594037927936` (wraps).
7. `delta_gas = 0 − (−72057594037927936) = 72057594037927936 > 0`.
8. Line 78: `gas_used += 72057594037927936` → wraps to `0`.
9. `total_gas_refund = u64::MAX`; check passes; `RefundInfo { gas_used: 0, … }` returned.
10. Operator fee = `0 × gas_price = 0`. User deposit fully refunded.

**Relevant code locations**: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L69-73)
```rust
    require!(
        tx_gas_limit.saturating_mul(ERGS_PER_GAS) < u64::MAX,
        InvalidTransaction::CallerGasLimitTooHigh,
        system
    )?;
```

**File:** zk_ee/src/system/mod.rs (L38-42)
```rust
/// Maximum value of EVM gas that can be represented as ergs in a u64.
pub const MAX_BLOCK_GAS_LIMIT: u64 = u64::MAX / ERGS_PER_GAS;
// Currently we don't have a separate individual tx gas limit,
// so the maximum tx gas limit is the same as the block gas limit.
pub const MAX_TX_GAS_LIMIT: u64 = MAX_BLOCK_GAS_LIMIT;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L78-138)
```rust
/// Resource creation policy for L1 transactions: log and saturate on errors
pub struct L1ResourcesPolicy;

impl<S: EthereumLikeTypes> ResourcesCreationErrorPolicy<S> for L1ResourcesPolicy {
    type Error = BootloaderSubsystemError;
    type ArithmeticError = L1ArithmeticError;

    fn native_underflow_error(operation: &'static str) -> Self::ArithmeticError {
        L1ArithmeticError::NativeUnderflow { operation }
    }

    fn intrinsic_gas_overflow_error(
        intrinsic_overhead: u64,
        gas_limit: u64,
    ) -> Self::ArithmeticError {
        L1ArithmeticError::IntrinsicGasOverflow {
            intrinsic_overhead,
            gas_limit,
        }
    }

    fn handle_arithmetic_error(
        system: &mut System<S>,
        error: Self::ArithmeticError,
    ) -> Result<u64, Self::Error> {
        match error {
            L1ArithmeticError::NativeUnderflow { operation } => {
                system_log!(
                    system,
                    "Native underflow during {}, saturating to 0 for L1 tx",
                    operation
                );
                Ok(0)
            }
            L1ArithmeticError::IntrinsicGasOverflow {
                intrinsic_overhead,
                gas_limit,
            } => {
                system_log!(
                    system,
                    "Gas limit {} < intrinsic gas {} for L1 tx, saturating to 0",
                    gas_limit,
                    intrinsic_overhead
                );
                Ok(0)
            }
        }
    }

    fn from_internal_error(error: BootloaderSubsystemError) -> Self::Error {
        error
    }

    fn from_validation_error(error: InvalidTransaction) -> Self::Error {
        // L1 transactions never have deployment validation, so this should never be called
        unreachable!(
            "L1ResourcesPolicy should never encounter validation error: {:?}",
            error
        )
    }
}
```
