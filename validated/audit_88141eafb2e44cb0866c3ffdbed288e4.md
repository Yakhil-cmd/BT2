### Title
`native_per_pubdata` Computed with Floor Division Understates Pubdata Cost, Systematically Undercharging Operators - (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

`native_per_pubdata` — the native-resource cost per byte of pubdata — is computed using floor (truncating) division (`wrapping_div`) in the L2 transaction validation path. The analogous `native_per_gas` ratio uses ceiling division (`div_ceil`) to ensure the user pays at least the true cost. The inconsistency means that whenever `pubdata_price` is not exactly divisible by `native_price`, the pubdata cost rate is understated, causing every pubdata-writing transaction to be charged slightly less native resource than the true cost. This systematically underpays the operator for pubdata costs, accumulating over time.

---

### Finding Description

In `validate_and_compute_fee_for_transaction`, the two key resource ratios are computed as follows:

**`native_per_gas` — uses ceiling division:**
```rust
u256_try_to_u64(&gas_price.div_ceil(native_price))
```

**`native_per_pubdata` — uses floor (wrapping) division:**
```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
``` [1](#0-0) 

The same floor-division pattern appears in the public API helper `validate_l2_tx_intrinsic_native_resources`:

```rust
// native_per_pubdata = pubdata_price / native_price
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
``` [2](#0-1) 

`native_per_pubdata` is then used in two downstream functions:

1. `create_resources_for_tx` — to pre-charge intrinsic pubdata overhead from the native budget:
   ```rust
   let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
   ``` [3](#0-2) 

2. `get_resources_to_charge_for_pubdata` — to charge native resources for actual pubdata written:
   ```rust
   let native = current_pubdata_spent
       .checked_mul(native_per_pubdata)
       .ok_or(out_of_native_resources!())?;
   ``` [4](#0-3) 

The double-resource accounting model converts native consumption back to gas via `deltaGas`:

```
deltaGas := (nativeUsed / nativePerGas) - gasUsed
``` [5](#0-4) 

If `native_per_pubdata` is understated, `native_used` is understated, `deltaGas` is understated, `gas_used` is understated, and the operator receives `gas_used * gas_price` — less than the true cost of the pubdata.

---

### Impact Explanation

**Concrete example:**
- `pubdata_price = 10^9 + 1`, `native_price = 10^9`
- True ratio: `1.000000001` native per pubdata byte
- `wrapping_div` (floor): `native_per_pubdata = 1`
- `div_ceil` (ceiling): `native_per_pubdata = 2`
- For a transaction writing 1,000 bytes of pubdata: charged 1,000 native instead of 2,000 native — a **50% undercharge** on pubdata costs in this edge case.

In the common case where `pubdata_price % native_price != 0`, the undercharge is exactly `N` native units per transaction (where `N` = pubdata bytes written), converted to `N / native_per_gas` gas units, and then to `N / native_per_gas * gas_price` tokens underpaid to the operator. This accumulates systematically across all pubdata-writing transactions.

The impact mirrors the IdleProvider finding: no single transaction causes a catastrophic loss, but the operator is systematically underpaid for pubdata costs over time, and the resource accounting is skewed.

---

### Likelihood Explanation

- Triggered by any unprivileged L2 transaction sender that writes storage (pubdata).
- Occurs whenever `pubdata_price % native_price != 0`, which is the common case since both are independently set market-driven values.
- No special permissions or conditions required beyond submitting a normal transaction.

---

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata`, consistent with how `native_per_gas` is computed:

In `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`:
```rust
// Before:
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After:
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs` line 427. [6](#0-5) [2](#0-1) 

---

### Proof of Concept

1. Set block context: `pubdata_price = 101`, `native_price = 100`, `eip1559_basefee = 100`.
2. Submit an L2 transaction that writes 10,000 bytes of pubdata (e.g., 312 storage slot writes).
3. Observe: `native_per_pubdata = floor(101/100) = 1`. True value: `ceil(101/100) = 2`.
4. Native charged for pubdata: `10,000 * 1 = 10,000`. True cost: `10,000 * 2 = 20,000`.
5. `native_used` is understated by 10,000 native units.
6. `deltaGas = (native_used / native_per_gas) - gas_used` is understated.
7. `gas_used` reported to the operator is understated.
8. Operator receives `gas_used * gas_price` — systematically less than the true pubdata cost.

The discrepancy is proportional to pubdata written and accumulates across all transactions where `pubdata_price % native_price != 0`.

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L135-143)
```rust
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
        }
    };

    // We checked native_price != 0 above
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
        .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

**File:** api/src/helpers.rs (L426-427)
```rust
    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L352-353)
```rust
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
    let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) {
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L430-432)
```rust
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
```

**File:** docs/double_resource_accounting.md (L48-50)
```markdown
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.
```
