### Title
Precision Loss in `native_per_pubdata` Calculation Causes Systematic Underpayment for Pubdata — (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

The `native_per_pubdata` rate is computed via integer floor division (`pubdata_price.wrapping_div(native_price)`), truncating the remainder. Because this truncated rate is then multiplied by the total pubdata bytes consumed, the rounding error compounds across every byte of pubdata a transaction writes. When `pubdata_price < native_price`, the rate collapses to zero and pubdata is entirely free in native resources. Any unprivileged user can exploit this by maximizing pubdata output (e.g., writing to many storage slots), causing the operator/protocol to bear the full DA cost without compensation.

---

### Finding Description

**Root cause — floor division in rate derivation:**

In `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs` line 142:

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

`wrapping_div` is integer floor division. The truncated `native_per_pubdata` is then used in `get_resources_to_charge_for_pubdata` (`basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs` line 430):

```rust
let native = current_pubdata_spent
    .checked_mul(native_per_pubdata)
    .ok_or(out_of_native_resources!())?;
```

The total native charged for pubdata is `floor(pubdata_price / native_price) * pubdata_bytes`. The correct amount is `(pubdata_price / native_price) * pubdata_bytes` (exact). The underpayment per transaction is:

```
underpayment = (pubdata_price % native_price) * pubdata_bytes / native_price
```

This is the direct analog of the StakingRewards bug: a rate is computed with floor division, and the truncation error is multiplied by a large count (pubdata bytes instead of reward duration).

**Extreme case — complete bypass:**

When `pubdata_price < native_price`, `native_per_pubdata = 0`. The user pays zero native resources for all pubdata. The existing test at `tests/instances/transactions/src/lib.rs` line 1236 already demonstrates this silently:

```rust
let native_price = U256::from(100);
let pubdata_price = U256::from(2);
// native_per_pubdata = floor(2/100) = 0 → pubdata is free
```

The same truncation is present in the public API helper at `api/src/helpers.rs` line 427:

```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

**Contrast with `native_per_gas`:**

`native_per_gas` is computed with `div_ceil` (rounds UP), which is protective for the protocol. `native_per_pubdata` uses floor division with no such protection, creating an asymmetry.

**Attacker-controlled entry path:**

1. Attacker submits a normal EIP-1559 transaction (no privileged access required).
2. Transaction body writes to many storage slots (e.g., a loop over `SSTORE`), maximizing `pubdata_bytes`.
3. `native_per_pubdata = floor(pubdata_price / native_price)` is computed with truncation.
4. The native resource charge for pubdata is `native_per_pubdata * pubdata_bytes`, which is less than the true cost.
5. The operator/protocol publishes the pubdata on-chain but receives less fee revenue than the actual DA cost.

---

### Impact Explanation

**Resource accounting bug — systematic underpayment for pubdata:**

- **Partial underpayment (always present):** For any `pubdata_price` not divisible by `native_price`, the truncation error `(pubdata_price % native_price)` is multiplied by every pubdata byte. A transaction writing 10,000 bytes with `pubdata_price = native_price - 1` underpays by `≈ 10,000` native units (≈100% of the pubdata cost).
- **Complete bypass (when `pubdata_price < native_price`):** `native_per_pubdata = 0`; the user pays zero native resources for all pubdata. The operator bears the full DA cost.
- **Financial loss to operator/protocol:** The operator publishes pubdata on-chain (real cost) but is not compensated. The user's native resource budget is not correctly reduced, allowing them to generate more pubdata than they can afford.
- **Amplification by attacker:** An unprivileged user can maximize pubdata output to amplify the underpayment, up to the block's `pubdata_limit`.

---

### Likelihood Explanation

- `pubdata_price` and `native_price` are real block-level parameters set by the operator and observed on live ZKsync networks (confirmed by `tests/block_reexecutor/src/main.rs` lines 148–149).
- The truncation is present in every block where `pubdata_price % native_price != 0`, which is the common case.
- The complete bypass (`native_per_pubdata = 0`) occurs whenever `pubdata_price < native_price`, a realistic configuration (e.g., `pubdata_price = 2`, `native_price = 100` as shown in the existing test).
- No privileged access, leaked keys, or external oracle manipulation is required. Any user submitting a pubdata-heavy transaction triggers the bug.

---

### Recommendation

Replace the floor division with ceiling division for `native_per_pubdata`, consistent with how `native_per_gas` is computed:

```rust
// Before (floor division — truncates remainder):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After (ceiling division — rounds up, protective for protocol):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs` line 427. Additionally, add a validation check that `native_per_pubdata > 0` when `pubdata_price > 0` to prevent the complete-bypass case.

---

### Proof of Concept

**Scenario: `pubdata_price = native_price - 1` (complete bypass)**

Parameters:
- `native_price = 1000`
- `pubdata_price = 999`
- Transaction writes to 500 storage slots → ~16,000 bytes of pubdata

Computation:
```
native_per_pubdata = floor(999 / 1000) = 0
native_charged_for_pubdata = 0 * 16000 = 0
actual_cost = (999 / 1000) * 16000 ≈ 15,984 native units
underpayment = 15,984 native units (≈ 100%)
```

The user pays zero native resources for 16,000 bytes of pubdata. The operator publishes this data on-chain at full cost with no compensation.

**Scenario: Partial underpayment (always present)**

Parameters:
- `native_price = 100`
- `pubdata_price = 150` (50% above native_price)
- Transaction generates 10,000 bytes of pubdata

Computation:
```
native_per_pubdata = floor(150 / 100) = 1
native_charged = 1 * 10000 = 10,000 native units
actual_cost = (150 / 100) * 10000 = 15,000 native units
underpayment = 5,000 native units (33%)
```

The existing test at `tests/instances/transactions/src/lib.rs:1236` already demonstrates the zero-rate case silently (`pubdata_price = 2`, `native_price = 100` → `native_per_pubdata = 0`) without asserting that pubdata is correctly charged. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L131-138)
```rust
            u256_try_to_u64(&system.get_eip1559_basefee().div_ceil(native_price)).ok_or(
                TxError::Validation(InvalidTransaction::NativeResourcesAreTooExpensive),
            )?
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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L427-434)
```rust
    let current_pubdata_spent = system
        .net_pubdata_used()?
        .saturating_sub(base_pubdata.unwrap_or(0));
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
    let native = <S::Resources as zk_ee::system::Resources>::Native::from_computational(native);
    Ok((current_pubdata_spent, S::Resources::from_native(native)))
```

**File:** api/src/helpers.rs (L426-427)
```rust
    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-73)
```rust
        let delta_gas = if native_per_gas == 0 {
            0
        } else {
            (native_used / native_per_gas) as i64 - (gas_used as i64)
        };
```

**File:** tests/instances/transactions/src/lib.rs (L1235-1237)
```rust
    let native_price = U256::from(100);
    let pubdata_price = U256::from(2);

```
