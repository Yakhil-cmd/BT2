### Title
Truncating Integer Division in `native_per_pubdata` Computation Rounds to Zero, Enabling Free Pubdata Publication - (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

The `native_per_pubdata` ratio used to charge native resources for L2 pubdata is computed with truncating (floor) integer division. When `pubdata_price < native_price`, the result rounds to zero. This makes pubdata effectively free in native-resource terms, allowing any unprivileged transaction sender to publish up to the block pubdata limit without paying the corresponding native resource cost, causing the operator to bear uncompensated L1 data-availability costs.

---

### Finding Description

In `validate_and_compute_fee_for_transaction`, the ratio of native resources per byte of pubdata is computed as:

```rust
// basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs, line 142
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

`wrapping_div` performs truncating (floor) integer division. When `pubdata_price < native_price`, the result is `0`.

This is inconsistent with how `native_per_gas` is computed on the very same lines above, which correctly uses ceiling division:

```rust
// basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs, line 135
u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
    InvalidTransaction::NativeResourcesAreTooExpensive,
))?
```

The same truncating division bug is present in the public API helper:

```rust
// api/src/helpers.rs, line 427
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

When `native_per_pubdata == 0`, the downstream charging functions produce zero cost for any amount of pubdata:

**1. Intrinsic pubdata overhead is zeroed out** in `create_resources_for_tx`:
```rust
// basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs, line 352
let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
// = 0 * intrinsic_pubdata = 0
```

**2. Execution pubdata is uncharged** in `get_resources_to_charge_for_pubdata`:
```rust
// basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs, line 430-431
let native = current_pubdata_spent
    .checked_mul(native_per_pubdata)  // = pubdata_bytes * 0 = 0
    .ok_or(out_of_native_resources!())?;
```

**3. The `deltaGas` adjustment is suppressed** in `compute_gas_refund`:
```rust
// basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs, line 64
let native_used = full_native_limit.saturating_sub(resources.native().remaining().as_u64());
// native_used is low because pubdata consumed 0 native, so deltaGas is 0 or negative
```

The net effect is that the user's `gas_used` does not increase to cover pubdata costs, and the operator is underpaid for the L1 data-availability work.

---

### Impact Explanation

**Vulnerability class:** Resource accounting bug — integer division truncation causes `native_per_pubdata` to round to zero, bypassing the native-resource charge for pubdata.

When `pubdata_price < native_price` (a realistic operator configuration), any L2 transaction sender can:
- Write to many storage slots (generating large pubdata) at zero native-resource cost
- Publish up to the block pubdata limit per transaction without paying for it
- Force the operator to pay L1 data-availability costs (calldata or blob fees) without receiving compensation

The operator sets `pubdata_price` to recover L1 DA costs. If `native_per_pubdata` truncates to zero, the `deltaGas` mechanism does not add extra gas to cover pubdata, so the user pays only for EVM computation, not for the data they publish. The operator's revenue shortfall equals `pubdata_price * pubdata_bytes_published` per affected transaction.

---

### Likelihood Explanation

The condition `pubdata_price < native_price` is realistic. Both values are operator-set block-level parameters. `native_price` reflects the cost of a single RISC-V proving cycle; `pubdata_price` reflects the cost of one byte of L1 data. Their relative magnitudes depend on market conditions and operator configuration. No special privilege is required — any standard L2 transaction that writes to storage triggers this path. The attacker only needs to submit a transaction when this condition holds.

---

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata`, consistent with how `native_per_gas` is computed:

```rust
// basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs, line 142
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs` line 427.

---

### Proof of Concept

**Setup:** Operator sets `native_price = 1000`, `pubdata_price = 999` (both are valid U256 values; `pubdata_price < native_price`).

**Computation:**
```
native_per_pubdata = pubdata_price.wrapping_div(native_price)
                   = 999 / 1000
                   = 0   (truncating integer division)
```

**Effect in `get_resources_to_charge_for_pubdata`:**
```
native = current_pubdata_spent.checked_mul(0) = 0
```

A transaction that writes to 100 storage slots (generating ~3,200 bytes of pubdata) pays:
- With correct ceiling division: `ceil(999/1000) = 1` native unit per byte → 3,200 native units charged
- With truncating division: `0` native units charged → pubdata is free

The `deltaGas` adjustment in `compute_gas_refund` also produces zero because `native_used` does not include pubdata cost, so `gas_used` is not increased to compensate. The operator receives payment only for EVM computation gas, not for the 3,200 bytes of pubdata it must publish to L1. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L351-353)
```rust
    // Charge intrinsic pubdata
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
    let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) {
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L429-432)
```rust
        .saturating_sub(base_pubdata.unwrap_or(0));
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L63-79)
```rust
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
```
