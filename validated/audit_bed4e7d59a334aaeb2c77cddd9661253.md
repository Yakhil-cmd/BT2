### Title
Integer Division Truncation of `native_per_pubdata` to Zero Allows Pubdata to Be Free in Native Resource Terms - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

When `pubdata_price < native_price`, the floor division `pubdata_price.wrapping_div(native_price)` truncates to `0`, setting `native_per_pubdata = 0`. This means pubdata consumption is never charged against the transaction's native resource budget, diverging from the intended formula and allowing a transaction sender to generate arbitrary pubdata (up to the block pubdata limit) without consuming any native resources for it.

---

### Finding Description

In `validate_and_compute_fee_for_transaction` in `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs` at line 142:

```rust
// We checked native_price != 0 above
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

`wrapping_div` performs floor (truncating) integer division. When `pubdata_price < native_price` (e.g., `pubdata_price = 50`, `native_price = 100`), the result is `0`. This zero value propagates through the entire fee pipeline:

1. **Intrinsic pubdata overhead** in `create_resources_for_tx` (`gas_helpers.rs` line 352):
   ```rust
   let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
   // = 0 * intrinsic_pubdata = 0
   ```
   The native limit is not reduced for intrinsic pubdata at all.

2. **Post-execution pubdata charge** in `get_resources_to_charge_for_pubdata` (`gas_helpers.rs` line 430):
   ```rust
   let native = current_pubdata_spent.checked_mul(native_per_pubdata)...;
   // = current_pubdata_spent * 0 = 0
   ```
   No native resources are charged for any pubdata generated during execution.

The identical truncation also appears in `api/src/helpers.rs` line 427:
```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

Note the asymmetry: `native_per_gas` is computed with **ceiling** division (`div_ceil`) to avoid rounding to zero, but `native_per_pubdata` uses floor division (`wrapping_div`), creating an inconsistency that silently zeroes out pubdata costs.

---

### Impact Explanation

When `native_per_pubdata = 0`, the transaction's native resource budget is entirely available for computation regardless of how much pubdata the transaction generates. A transaction sender can:

- Write to many storage slots (each generating ~32 bytes of pubdata) without consuming any native resources for those writes.
- Use the full `nativeLimit = gasLimit * nativePerGas` for computation, while also consuming pubdata up to the block's pubdata limit at zero native cost.

This diverges from the intended formula (`native_per_pubdata = pubdata_price / native_price`) and breaks the double-resource accounting model described in `docs/double_resource_accounting.md`. The native resource budget no longer correctly reflects the true cost of the transaction's pubdata footprint, allowing transactions to be more resource-intensive than their fee payment should permit.

---

### Likelihood Explanation

This condition is triggered whenever the operator sets `pubdata_price < native_price`. This is a realistic operational scenario: `native_price` reflects the cost of a single proving cycle (a compute-heavy metric), while `pubdata_price` reflects the cost of publishing one byte of data to L1 (a separate, potentially cheaper metric). In periods of low L1 data costs relative to proving costs, `pubdata_price < native_price` is expected. Any unprivileged transaction sender can exploit this condition by submitting pubdata-heavy transactions whenever it holds.

---

### Recommendation

Replace `wrapping_div` with `div_ceil` for the `native_per_pubdata` calculation, consistent with how `native_per_gas` is computed:

```rust
// Before (floor division — can produce 0):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After (ceiling division — consistent with native_per_gas):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs`. This ensures that any non-zero `pubdata_price` results in at least 1 native unit charged per pubdata byte, preserving the intended resource accounting invariant.

---

### Proof of Concept

**Setup:**
- `native_price = 100`
- `pubdata_price = 99`
- `native_per_pubdata = 99 / 100 = 0` (floor division)
- `gas_limit = 1_000_000`, `gas_price = 100` → `native_per_gas = 1`, `native_limit = 1_000_000`

**Attack:**
1. Sender submits a transaction that writes to 1,000 storage slots (generating ~32,000 bytes of pubdata).
2. Because `native_per_pubdata = 0`, `get_resources_to_charge_for_pubdata` returns 0 native for all 32,000 bytes.
3. The full `native_limit = 1_000_000` remains available for computation.
4. The transaction uses both its full native computation budget **and** generates 32,000 bytes of pubdata — paying only for computation, not for pubdata.

**Expected (correct) behavior:**
- `native_per_pubdata` should be `ceil(99/100) = 1`
- Pubdata charge = `32,000 * 1 = 32,000` native units deducted from the native limit
- Only `1,000,000 - 32,000 = 968,000` native units remain for computation [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L429-434)
```rust
        .saturating_sub(base_pubdata.unwrap_or(0));
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
    let native = <S::Resources as zk_ee::system::Resources>::Native::from_computational(native);
    Ok((current_pubdata_spent, S::Resources::from_native(native)))
```

**File:** docs/double_resource_accounting.md (L37-48)
```markdown
First we define the ratio between EVM gas and native resource as:
  `nativePerGas := gasPrice/nativePrice`
Note: for call simulation we use a constant for it, as gasPrice might be set to 0.

Next we define the limit for the native resource as:
  `nativeLimit := gasLimit * nativePerGas`

Then we process the transaction, charging both Ergs for EE execution and native resource for any kind of computation (EE, bootloader or system work).

If execution doesn't run out of native resources, we first charge for pubdata from native resource.
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`
```
