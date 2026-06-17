### Title
Truncating Floor Division in `native_per_pubdata` Calculation Causes Systematic Underpayment for Pubdata - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

In the ZK transaction validation path, `native_per_pubdata` is computed using floor (truncating) division via `wrapping_div`, while `native_per_gas` is computed using ceiling division via `div_ceil`. This asymmetry causes the protocol to systematically undercharge every transaction for pubdata whenever `pubdata_price` is not an exact multiple of `native_price`. The undercharge propagates through the native resource accounting and reduces the final `gas_used` charged to the sender, meaning the operator receives less fee than the correct pubdata cost warrants. Any unprivileged L2 transaction sender can trigger this path.

---

### Finding Description

In `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`, the two rate conversions are computed back-to-back:

```rust
// line 135 — ceiling division: user always pays at least the correct native per gas
u256_try_to_u64(&gas_price.div_ceil(native_price))

// line 142 — floor division: user pays LESS than the correct native per pubdata
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

`native_per_gas` intentionally rounds **up** so the protocol is never under-compensated for computation. `native_per_pubdata` rounds **down**, so the protocol is always under-compensated for pubdata whenever `pubdata_price % native_price != 0`.

The truncated `native_per_pubdata` flows into two downstream sites:

1. **`get_resources_to_charge_for_pubdata`** (`gas_helpers.rs` line 431):
   ```rust
   let native = current_pubdata_spent.checked_mul(native_per_pubdata)...
   ```
   Each pubdata byte costs `native_per_pubdata` native units instead of the correct `⌈pubdata_price / native_price⌉`, so `native_used` is understated by up to `(native_price − 1)` native units per pubdata byte.

2. **`compute_gas_refund`** (`refund_calculation.rs` line 72):
   ```rust
   let delta_gas = (native_used / native_per_gas) as i64 - (gas_used as i64);
   if delta_gas > 0 { gas_used += delta_gas as u64; }
   ```
   Because `native_used` is already understated, `delta_gas` is smaller than it should be, so `gas_used` is not bumped up to the correct level, and the sender pays fewer tokens.

The identical floor-division bug is also present in the off-chain helper `api/src/helpers.rs` line 427:
```rust
// native_per_pubdata = pubdata_price / native_price   ← floor, not ceil
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```
This means the API-side pre-validation (`validate_l2_tx_intrinsic_native_resources`) mirrors the bootloader's under-accounting, so the discrepancy is invisible to off-chain tooling.

---

### Impact Explanation

For every L2 ZK transaction where `pubdata_price % native_price ≠ 0`:

- The rounding error per pubdata byte is `pubdata_price % native_price` native units (up to `native_price − 1`).
- For a transaction producing `P` pubdata bytes, the total native shortfall is up to `P × (native_price − 1)`.
- This converts to a gas shortfall of up to `P × (native_price − 1) / native_per_gas` gas units.
- The operator receives `gas_price × shortfall` fewer tokens than the correct pubdata cost.

Because pubdata bytes scale with state-diff size (storage writes, deployments, etc.), a transaction that writes to many storage slots amplifies the loss linearly. The loss is bounded per transaction by `gas_limit × gas_price` (the maximum fee), but the systematic nature means every block leaks value to every sender who generates pubdata.

---

### Likelihood Explanation

- `pubdata_price % native_price ≠ 0` is the common case; both prices are set by the operator/oracle and there is no enforcement that one divides the other.
- Every ordinary L2 transaction that touches storage (ERC-20 transfers, contract interactions, deployments) generates pubdata and hits this path.
- No special privileges, no governance access, no oracle manipulation required — any unprivileged EOA submitting a standard transaction triggers the bug.

---

### Recommendation

Replace the floor division with ceiling division for `native_per_pubdata` in both locations, mirroring the treatment of `native_per_gas`:

**`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs` line 142:**
```rust
// Before (floor):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After (ceiling):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

**`api/src/helpers.rs` line 427:**
```rust
// Before:
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;

// After:
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price)).ok_or(())?;
```

Additionally, consider whether `native_used / native_per_gas` at `refund_calculation.rs` line 72 should also use ceiling division to avoid a secondary one-gas-unit rounding loss per transaction.

---

### Proof of Concept

**Setup:** `pubdata_price = 7`, `native_price = 3`, `gas_price = 9`, `gas_limit = 100_000`, transaction writes 500 storage slots (≈ 16,000 pubdata bytes).

**Step 1 — `native_per_gas` (correct, ceiling):**
```
native_per_gas = ⌈9 / 3⌉ = 3
```

**Step 2 — `native_per_pubdata` (buggy, floor):**
```
native_per_pubdata = ⌊7 / 3⌋ = 2   ← should be ⌈7/3⌉ = 3
```

**Step 3 — native charged for pubdata:**
```
native_for_pubdata = 16_000 × 2 = 32_000   ← correct would be 16_000 × 3 = 48_000
```

**Step 4 — `delta_gas` adjustment:**
```
native_used ≈ 32_000
delta_gas = 32_000 / 3 = 10_666   ← correct would be 48_000 / 3 = 16_000
```

**Step 5 — fee shortfall:**
```
gas shortfall = 16_000 − 10_666 = 5_334 gas
token shortfall = 5_334 × gas_price = 5_334 × 9 = 48_006 native tokens
```

The operator is underpaid by 48,006 native tokens on a single transaction. Across a busy block with many pubdata-heavy transactions, the cumulative loss is proportional to total pubdata produced. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** api/src/helpers.rs (L420-427)
```rust
    // native_per_gas = ceil(gas_price / native_price)
    if native_price.is_zero() {
        return Err(());
    }
    let native_per_gas = u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(())?;

    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L430-432)
```rust
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-79)
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
```
