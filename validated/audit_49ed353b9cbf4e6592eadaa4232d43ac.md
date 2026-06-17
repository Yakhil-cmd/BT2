### Title
Silent `saturating_mul` Overflow in Native Resource Limit Computation Inflates Pubdata Budget — (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`, `refund_calculation.rs`)

---

### Summary

Two `saturating_mul` calls that compute the native resource limit for a transaction silently cap at `u64::MAX` when `native_per_gas × gas_limit` overflows. This inflates the `withheld` (pubdata) native budget to `u64::MAX − MAX_NATIVE_COMPUTATIONAL`, allowing a transaction to write far more pubdata than it paid for. A second overflow in the refund path then corrupts the `delta_gas` adjustment, breaking the native-to-gas reconciliation.

---

### Finding Description

**Location 1 — `validation_impl.rs` line 144** [1](#0-0) 

```rust
let native_per_gas = {
    ...
    u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
        InvalidTransaction::NativeResourcesAreTooExpensive,
    ))?
};
// ...
let native_prepaid_from_gas = native_per_gas.saturating_mul(tx_gas_limit);  // line 144
```

`native_per_gas` is a `u64` (up to `u64::MAX`). `tx_gas_limit` is bounded by `MAX_BLOCK_GAS_LIMIT = u64::MAX / ERGS_PER_GAS = u64::MAX / 256`. When `native_per_gas > 256`, the product can exceed `u64::MAX`. `saturating_mul` silently returns `u64::MAX` instead of propagating an error. [2](#0-1) 

**Location 2 — `gas_helpers.rs` `create_resources_for_tx`**

The saturated `native_prepaid_from_gas = u64::MAX` is passed directly as `native_limit`: [3](#0-2) 

```rust
let native_limit = if cfg!(feature = "unlimited_native") || free_native {
    u64::MAX - 1
} else {
    native_prepaid_from_gas   // ← u64::MAX when overflowed
};
// ...
let (native_limit, withheld) = if native_limit <= MAX_NATIVE_COMPUTATIONAL {
    (native_limit, S::Resources::from_ergs(Ergs::empty()))
} else {
    let withheld = native_limit - MAX_NATIVE_COMPUTATIONAL;  // ≈ u64::MAX
    (MAX_NATIVE_COMPUTATIONAL, S::Resources::from_native(withheld))
};
```

With `native_limit = u64::MAX`, the `withheld` pubdata budget becomes `u64::MAX − MAX_NATIVE_COMPUTATIONAL`, which is effectively unlimited. The transaction can exhaust pubdata (state-diff writes) without running out of native resources.

**Location 3 — `refund_calculation.rs` lines 62 and 72** [4](#0-3) 

```rust
let full_native_limit = if ... {
    u64::MAX - 1
} else {
    gas_limit.saturating_mul(native_per_gas)  // line 62 — same overflow
};
let native_used = full_native_limit.saturating_sub(resources.native().remaining().as_u64());
// native_used ≈ u64::MAX

let delta_gas = (native_used / native_per_gas) as i64 - (gas_used as i64);  // line 72
```

`native_used / native_per_gas` can exceed `i64::MAX` and wraps to a large negative value on the `as i64` cast. This makes `delta_gas` negative when it should be positive, suppressing the native-to-gas reconciliation charge and allowing the user to underpay for native resource consumption.

---

### Impact Explanation

1. **Pubdata underpayment (resource accounting bug):** The `withheld` native budget is inflated to `≈ u64::MAX`. A transaction can write an unbounded amount of pubdata (storage diffs) without exhausting native resources, forcing the operator/prover to absorb the excess proving and DA cost.

2. **Incorrect gas refund / delta_gas corruption:** The `as i64` wrap in `refund_calculation.rs` line 72 makes `delta_gas` negative, bypassing the `if delta_gas > 0` guard. The user is not charged the extra gas that should compensate for native resource consumption, resulting in an undercharge.

Both effects are triggered by the same root cause and are reachable by any unprivileged L2 transaction sender.

---

### Likelihood Explanation

The overflow condition is `native_per_gas > 256` AND `tx_gas_limit > u64::MAX / native_per_gas`. Since `MAX_BLOCK_GAS_LIMIT ≈ 7.2 × 10¹⁶`, any `native_per_gas ≥ 257` combined with a gas limit above `u64::MAX / native_per_gas` triggers it. A concrete example:

- `native_per_gas = 1000` (gas price = 1000 × native_price)
- `tx_gas_limit = 2 × 10¹⁶` (well within `MAX_BLOCK_GAS_LIMIT`)
- `1000 × 2 × 10¹⁶ = 2 × 10¹⁹ > u64::MAX ≈ 1.84 × 10¹⁹` → saturates

The user must hold enough ETH to pass the balance check (`gas_price × gas_limit`), but the pubdata budget they receive is disproportionately large relative to what they paid.

---

### Recommendation

Replace both `saturating_mul` calls with `checked_mul` and return an appropriate error on overflow:

**`validation_impl.rs` line 144:**
```rust
let native_prepaid_from_gas = native_per_gas
    .checked_mul(tx_gas_limit)
    .ok_or(TxError::Validation(InvalidTransaction::NativeResourcesAreTooExpensive))?;
```

**`refund_calculation.rs` line 62:**
```rust
let full_native_limit = gas_limit
    .checked_mul(native_per_gas)
    .unwrap_or(u64::MAX - 1);  // saturate only here, after validation has already passed
```

Additionally, the `as i64` cast on line 72 of `refund_calculation.rs` should be guarded:
```rust
let native_gas_equiv = native_used / native_per_gas;
let delta_gas = if native_gas_equiv > i64::MAX as u64 {
    i64::MAX
} else {
    native_gas_equiv as i64 - gas_used as i64
};
```

---

### Proof of Concept

1. Deploy a ZKsync OS instance with `native_price = 1` (or any small value).
2. Submit an L2 EIP-1559 transaction with:
   - `max_fee_per_gas = 1000` (so `native_per_gas = 1000`)
   - `gas_limit = 2_000_000_000_000_0001` (≈ `2 × 10¹³`, within `MAX_BLOCK_GAS_LIMIT`)
   - Sufficient ETH balance to pass the balance check
3. Observe that `native_prepaid_from_gas = saturating_mul(1000, 2×10¹³) = 2×10¹⁶ < u64::MAX` — adjust `gas_limit` upward until `native_per_gas × gas_limit > u64::MAX`.
4. Confirm via logging that `withheld ≈ u64::MAX − MAX_NATIVE_COMPUTATIONAL` in `create_resources_for_tx`.
5. Execute a transaction body that writes many storage slots; observe that the transaction does not run out of native resources despite the pubdata volume exceeding what the fee should cover.
6. Confirm in `refund_calculation.rs` that `native_used ≈ u64::MAX` and `delta_gas` is negative (or zero) due to the `as i64` wrap, resulting in no additional gas charge for the native consumption. [5](#0-4) [4](#0-3) [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L121-144)
```rust
    let native_per_gas = {
        if native_price.is_zero() {
            return Err(internal_error!("Native price cannot be 0").into());
        }

        if cfg!(feature = "resources_for_tester") {
            crate::bootloader::constants::TESTER_NATIVE_PER_GAS
        } else if Config::SIMULATION && gas_price.is_zero() {
            // For simulation, if gas price isn't set, we use base fee
            // for native calculation
            u256_try_to_u64(&system.get_eip1559_basefee().div_ceil(native_price)).ok_or(
                TxError::Validation(InvalidTransaction::NativeResourcesAreTooExpensive),
            )?
        } else {
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
        }
    };

    // We checked native_price != 0 above
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
        .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
    let native_prepaid_from_gas = native_per_gas.saturating_mul(tx_gas_limit);
```

**File:** basic_bootloader/src/bootloader/constants.rs (L39-39)
```rust
pub const MAX_BLOCK_GAS_LIMIT: u64 = u64::MAX / ERGS_PER_GAS;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L344-380)
```rust
    // Note: for zero gas price, we use "unlimited native"
    let native_limit = if cfg!(feature = "unlimited_native") || free_native {
        u64::MAX - 1 // So any saturation below can not be subtracted from it
    } else {
        native_prepaid_from_gas
    };

    // Charge intrinsic pubdata
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
    let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) {
        Some(val) => val,
        None => P::handle_arithmetic_error(
            system,
            P::native_underflow_error("subtracting pubdata overhead"),
        )?,
    };

    // EVM tester requires high native limits, so for it we never hold off resources.
    // But for the real world, we bound the available resources.

    #[cfg(feature = "resources_for_tester")]
    let withheld = S::Resources::from_ergs(Ergs::empty());

    #[cfg(not(feature = "resources_for_tester"))]
    let (native_limit, withheld) = if native_limit <= MAX_NATIVE_COMPUTATIONAL {
        (native_limit, S::Resources::from_ergs(Ergs::empty()))
    } else {
        let withheld =
            <<S as zk_ee::system::SystemTypes>::Resources as Resources>::Native::from_computational(
                native_limit - MAX_NATIVE_COMPUTATIONAL,
            );

        (
            MAX_NATIVE_COMPUTATIONAL,
            S::Resources::from_native(withheld),
        )
    };
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L59-80)
```rust
    let full_native_limit = if cfg!(feature = "unlimited_native") || native_per_gas == 0 {
        u64::MAX - 1
    } else {
        gas_limit.saturating_mul(native_per_gas)
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
        // TODO: return delta_gas to gas_used?
```
