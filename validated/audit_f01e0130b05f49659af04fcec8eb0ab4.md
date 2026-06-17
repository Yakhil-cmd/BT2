### Title
Truncating Integer Division in `native_per_pubdata` Computation Causes Systematic Downward Bias in Pubdata Cost Accounting — (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

ZKsync OS computes `native_per_pubdata` using truncating (floor) integer division, while `native_per_gas` uses ceiling division. This directional asymmetry introduces a systematic downward bias in the native resource charged for pubdata, analogous to the DSMath "round half up" bias. The bias compounds through the `delta_gas` calculation in `refund_calculation.rs`, causing users to consistently underpay for pubdata-heavy transactions in the native resource dimension.

---

### Finding Description

**Root cause — asymmetric rounding in resource ratio computation:**

In `validation_impl.rs` line 142, `native_per_pubdata` is computed with `wrapping_div` (floor/truncating division):

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

In contrast, `native_per_gas` on line 135 uses `div_ceil` (ceiling division):

```rust
u256_try_to_u64(&gas_price.div_ceil(native_price))
```

The same truncating pattern appears in `api/src/helpers.rs` line 427:

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

**Bias propagation through `delta_gas`:**

In `refund_calculation.rs` lines 69–79, the `delta_gas` adjustment also uses truncating integer division:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};

if delta_gas > 0 {
    gas_used += delta_gas as u64;
}
```

Because `native_per_pubdata` is underestimated, the native charged for pubdata (`current_pubdata_spent * native_per_pubdata`) is lower than the true cost. This reduces `native_used`. The reduced `native_used` then feeds into `native_used / native_per_gas`, which is itself truncated, further underestimating `delta_gas`. The result is that `gas_used` is underestimated and the user receives a larger-than-correct refund.

**Compounding effect (analogous to DSMath):**

The documentation in `docs/double_resource_accounting.md` defines:
```
deltaGas := (nativeUsed / nativePerGas) - gasUsed
```

Both divisions truncate. Each truncation introduces a downward error of up to `(divisor - 1)` units. When the two truncations compound across a pubdata-heavy transaction, the cumulative undercharge is:

```
undercharge_native ≈ (pubdata_price mod native_price) * pubdata_bytes / native_price
undercharge_gas    ≈ floor(undercharge_native / native_per_gas)
```

This is structurally identical to the DSMath scenario: repeated truncating divisions on intermediate results produce a systematic bias that diverges from the ideal result as pubdata usage grows.

---

### Impact Explanation

Every L2 transaction that writes pubdata when `pubdata_price mod native_price ≠ 0` underpays for native resource. The per-transaction undercharge in native units is bounded by:

```
max_undercharge = (native_price - 1) * pubdata_bytes / native_price  ≈  pubdata_bytes
```

For a transaction writing the maximum allowed pubdata, this can be on the order of tens of thousands of native units. Across a high-throughput chain, the cumulative shortfall in native resource coverage for pubdata grows unboundedly. The operator/prover absorbs the uncovered proving cost. Because `native_per_gas` is simultaneously overestimated (via `div_ceil`), users also receive a slightly larger native budget than strictly required, compounding the benefit to the user.

---

### Likelihood Explanation

The condition `pubdata_price mod native_price ≠ 0` holds for almost all realistic operator-set price pairs, since `pubdata_price` and `native_price` are independently configured U256 values. The bias is therefore present in virtually every L2 transaction that touches storage or emits events. Any unprivileged sender submitting a standard EIP-1559 or legacy transaction triggers this path.

---

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata` to match the rounding direction used for `native_per_gas`:

```rust
// Before (truncates, undercharges pubdata):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))...;

// After (rounds up, consistent with native_per_gas):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))...;
```

Apply the same fix in `api/src/helpers.rs`. This ensures the native resource charged for pubdata is never less than the true cost, eliminating the systematic downward bias.

---

### Proof of Concept

**Setup:** `pubdata_price = 10`, `native_price = 3`, transaction writes 1 000 pubdata bytes.

**Current behaviour (truncating):**
```
native_per_pubdata = floor(10 / 3) = 3
native_charged     = 3 × 1000     = 3 000 native units
```

**Correct behaviour (ceiling):**
```
native_per_pubdata = ceil(10 / 3) = 4
native_charged     = 4 × 1000     = 4 000 native units
```

**Undercharge per transaction:** 1 000 native units (25 % of the true cost).

The undercharge then reduces `native_used`, which reduces `delta_gas` via the truncating division in `refund_calculation.rs` line 72, so the user also receives a slightly larger gas refund. Both errors are directionally consistent (downward bias), exactly mirroring the DSMath "round half up" accumulation described in the reference report. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** api/src/helpers.rs (L426-428)
```rust
    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;

```

**File:** docs/double_resource_accounting.md (L47-50)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.
```
