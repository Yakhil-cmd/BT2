### Title
`native_per_pubdata` Truncates to Zero via Integer Floor Division When `pubdata_price < native_price`, Bypassing Pubdata Cost Enforcement — (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

When the operator-set `pubdata_price` is less than `native_price`, the integer floor division used to compute `native_per_pubdata` truncates to zero. This silently disables all native-resource charging for pubdata, allowing any transaction sender to write up to the block's pubdata limit at zero native cost, causing the operator to bear L1 data-availability costs without collecting fees.

---

### Finding Description

In `validate_and_compute_fee_for_transaction`, `native_per_pubdata` is computed as:

```rust
// basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs:142
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

`wrapping_div` is integer floor division. When `pubdata_price < native_price` (e.g., `pubdata_price = 500`, `native_price = 1000`), the result is `0`. No error is returned; the zero value is silently accepted and propagated.

The same pattern appears in the public API helper:

```rust
// api/src/helpers.rs:427
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

By contrast, `native_per_gas` is computed with `div_ceil`, which guarantees a minimum of 1:

```rust
// basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs:135
u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(...)
```

This asymmetry means pubdata cost can silently become zero while gas cost cannot.

Once `native_per_pubdata = 0`, every downstream pubdata-charging call produces zero cost:

1. **`create_resources_for_tx`** — `intrinsic_pubdata_overhead = 0 * intrinsic_pubdata = 0`; no native is deducted for intrinsic pubdata at transaction setup.
2. **`get_resources_to_charge_for_pubdata`** — `native = current_pubdata_spent * 0 = 0`; no native is charged for execution pubdata.
3. **`check_enough_resources_for_pubdata`** — always returns `enough = true` because `resources_for_pubdata = 0`.

The `deltaGas` adjustment in `compute_gas_refund` also uses `native_per_gas`, not `native_per_pubdata`, so it does not compensate for the missing pubdata charge.

---

### Impact Explanation

When `pubdata_price < native_price`, any unprivileged transaction sender can write up to the block-level `pubdata_limit` bytes of state-diff pubdata without paying any native resource cost for it. The operator must still pay L1 data-availability costs for that pubdata, but collects no fee to cover them. This breaks the economic model of the double-resource accounting system and can cause the operator to run at a loss on pubdata-heavy workloads (e.g., contracts that write many storage slots).

---

### Likelihood Explanation

`native_price` and `pubdata_price` are independent operator-set block-level parameters. A configuration where `pubdata_price < native_price` is realistic: for example, when L1 calldata/blob costs are low relative to proving costs, an operator may set a low `pubdata_price` while keeping `native_price` higher to reflect proving complexity. No privileged access beyond normal transaction submission is required to exploit the resulting zero `native_per_pubdata`.

---

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata`, consistent with how `native_per_gas` is computed:

```rust
// Before (truncates to zero when pubdata_price < native_price):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After (rounds up, guarantees at least 1 when pubdata_price > 0):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs`. If a zero `native_per_pubdata` is intentionally allowed (e.g., when `pubdata_price == 0`), add an explicit zero-check and handle it as a distinct "free pubdata" policy rather than silently inheriting it from truncation.

---

### Proof of Concept

**Setup:** Operator sets `native_price = 1000`, `pubdata_price = 999`.

**Computation:**
- `native_per_pubdata = 999.wrapping_div(1000) = 0` ← truncates to zero
- `native_per_gas = ceil(gas_price / 1000)` ← at least 1 if gas_price > 0

**Effect in `get_resources_to_charge_for_pubdata`:**
```rust
// gas_helpers.rs:430-432
let native = current_pubdata_spent
    .checked_mul(native_per_pubdata)  // = current_pubdata_spent * 0 = 0
    .ok_or(out_of_native_resources!())?;
```

A transaction writing 100 storage slots (generating ~3200 bytes of pubdata) is charged `0` native for pubdata. `check_enough_resources_for_pubdata` returns `enough = true`. The transaction succeeds and the operator absorbs the L1 cost with no fee collected. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L134-138)
```rust
        } else {
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L141-143)
```rust
    // We checked native_price != 0 above
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
        .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

**File:** api/src/helpers.rs (L426-427)
```rust
    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L351-352)
```rust
    // Charge intrinsic pubdata
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L429-434)
```rust
        .saturating_sub(base_pubdata.unwrap_or(0));
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
    let native = <S::Resources as zk_ee::system::Resources>::Native::from_computational(native);
    Ok((current_pubdata_spent, S::Resources::from_native(native)))
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-73)
```rust
        let delta_gas = if native_per_gas == 0 {
            0
        } else {
            (native_used / native_per_gas) as i64 - (gas_used as i64)
        };
```
