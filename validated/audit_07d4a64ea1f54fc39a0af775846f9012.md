### Title
Division-Before-Multiplication Precision Loss in `native_per_pubdata` Calculation Causes Systematic Pubdata Underpayment - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

In `validation_impl.rs`, `native_per_pubdata` is computed using integer floor division (`wrapping_div`) before being multiplied by `pubdata_used`. This is the classic division-before-multiplication precision loss. The analogous `native_per_gas` calculation correctly uses `div_ceil`, but `native_per_pubdata` does not, causing the protocol to systematically undercharge every transaction that generates pubdata whenever `pubdata_price % native_price != 0`.

---

### Finding Description

In `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs` at line 142:

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

`wrapping_div` performs integer floor division, truncating the fractional part. This truncated `native_per_pubdata` is then multiplied by `current_pubdata_spent` in `gas_helpers.rs`:

```rust
let native = current_pubdata_spent
    .checked_mul(native_per_pubdata)
    .ok_or(out_of_native_resources!())?;
```

The same pattern is replicated in `api/src/helpers.rs` line 427:

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

By contrast, `native_per_gas` is computed with ceiling division throughout the codebase:

```rust
u256_try_to_u64(&gas_price.div_ceil(native_price))
```

The asymmetry is the root cause. The correct formula for `native_per_pubdata` should also use `div_ceil` to ensure the full pubdata cost is recovered.

**Concrete example:**
- `pubdata_price = 101`, `native_price = 10`
- `native_per_pubdata = 101 / 10 = 10` (floor, loses 1 unit per pubdata byte)
- Transaction uses 1,000 pubdata bytes
- Charged: `10 × 1,000 = 10,000` native
- Correct charge: `ceil(101/10) × 1,000 = 11 × 1,000 = 11,000` native
- Underpayment: 1,000 native per transaction

---

### Impact Explanation

Every L2 transaction that writes storage (generating pubdata) is undercharged for its pubdata cost whenever `pubdata_price % native_price != 0`. The operator receives fewer native tokens than the actual cost of posting pubdata to L1. This is a resource accounting bug: the protocol's pubdata cost recovery is systematically lower than the true cost, representing a direct financial loss to the operator/protocol proportional to `(pubdata_price % native_price) * pubdata_used / native_price` per transaction. At scale (many transactions, large pubdata), the cumulative loss is material.

---

### Likelihood Explanation

The condition `pubdata_price % native_price != 0` is the normal operating state. Both `pubdata_price` and `native_price` are set from oracle/block-context values that are independent of each other and will rarely be exact multiples. Any unprivileged user submitting a transaction that writes to storage (e.g., ERC-20 transfer, any state-changing call) triggers this path. No special privileges, governance access, or external oracle manipulation is required.

---

### Recommendation

Replace `wrapping_div` with `div_ceil` for the `native_per_pubdata` calculation, consistent with how `native_per_gas` is computed:

```rust
// Before (floor division — loses precision):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After (ceiling division — consistent with native_per_gas):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs` line 427.

---

### Proof of Concept

**Root cause — floor division in `native_per_pubdata`:** [1](#0-0) 

**Contrast — `native_per_gas` correctly uses ceiling division:** [2](#0-1) 

**Truncated `native_per_pubdata` is then multiplied by `current_pubdata_spent`:** [3](#0-2) 

**Same floor-division pattern replicated in the API helper:** [4](#0-3)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L430-432)
```rust
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
```

**File:** api/src/helpers.rs (L426-427)
```rust
    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```
