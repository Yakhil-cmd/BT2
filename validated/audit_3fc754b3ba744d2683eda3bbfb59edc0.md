### Title
Incorrect Rounding in `native_per_pubdata` Calculation Leads to Systematic Underpayment for Pubdata - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

### Summary
The `native_per_pubdata` ratio — which controls how much native resource is charged per byte of pubdata — is computed using floor division (`wrapping_div`), while the analogous `native_per_gas` ratio is correctly computed using ceiling division (`div_ceil`). This inconsistency causes every transaction that publishes pubdata to be systematically undercharged for native resources whenever `pubdata_price % native_price != 0`, allowing users to consume slightly more proving capacity than they paid for.

### Finding Description

In `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`, the two key resource ratios are computed as follows:

```rust
// native_per_gas: uses div_ceil — correct, favors protocol
u256_try_to_u64(&gas_price.div_ceil(native_price))...

// native_per_pubdata: uses wrapping_div (floor) — incorrect, favors user
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))...
``` [1](#0-0) 

The same floor-division pattern is replicated in the public API helper:

```rust
// native_per_pubdata = pubdata_price / native_price  (floor)
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
``` [2](#0-1) 

`native_per_pubdata` is then used in two places:

1. **Intrinsic pubdata pre-charge** — `intrinsic_pubdata_overhead = native_per_pubdata * intrinsic_pubdata` is subtracted from the native limit before execution begins.
2. **Runtime pubdata charge** — `native = current_pubdata_spent * native_per_pubdata` is charged after execution. [3](#0-2) [4](#0-3) 

Because `native_per_pubdata` is rounded down, both charges are slightly lower than the true cost. The user's effective native limit is slightly higher than it should be, and the operator receives slightly less compensation for pubdata.

The documentation confirms the intended formula is `nativePerGas := gasPrice / nativePrice` (conceptually a ratio), but the implementation applies ceiling for gas and floor for pubdata without justification for the asymmetry. [5](#0-4) 

### Impact Explanation

**Impact: Low.** For each pubdata byte, the underpayment is at most `1` native unit (the rounding error of a single division). For a transaction publishing `N` pubdata bytes, the total underpayment is at most `N` native units. Native units represent RISC-V proving cycles; the monetary value of the shortfall is negligible per transaction. However, it is a systematic, non-zero underpayment that accumulates across all transactions with pubdata whenever `pubdata_price % native_price != 0`. The operator/protocol is the party that bears this loss.

### Likelihood Explanation

**Likelihood: High.** The condition `pubdata_price % native_price != 0` is the common case in production — `pubdata_price` and `native_price` are independent operator-set parameters with no alignment requirement. Every L2 transaction that writes storage (generating pubdata) will trigger this path. The bug is always active unless the operator deliberately sets `pubdata_price` to be an exact multiple of `native_price`.

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata`, matching the treatment of `native_per_gas`:

```diff
- let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
+ let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
      .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs`:

```diff
- let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
+ let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price)).ok_or(())?;
```

### Proof of Concept

Consider:
- `pubdata_price = 101`, `native_price = 10`
- `native_per_pubdata` (floor) = `101 / 10 = 10`
- `native_per_pubdata` (ceil, correct) = `ceil(101 / 10) = 11`

For a transaction publishing 1 000 pubdata bytes:
- Charged: `10 × 1000 = 10 000` native units
- Should be charged: `11 × 1000 = 11 000` native units
- Underpayment: **1 000 native units** per transaction

Any unprivileged L2 transaction sender can trigger this path by submitting a transaction that writes to storage (generating pubdata). No special access is required; the rounding error is structural and occurs on every such transaction when `pubdata_price % native_price != 0`.

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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L351-359)
```rust
    // Charge intrinsic pubdata
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
    let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) {
        Some(val) => val,
        None => P::handle_arithmetic_error(
            system,
            P::native_underflow_error("subtracting pubdata overhead"),
        )?,
    };
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

**File:** docs/double_resource_accounting.md (L37-42)
```markdown
First we define the ratio between EVM gas and native resource as:
  `nativePerGas := gasPrice/nativePrice`
Note: for call simulation we use a constant for it, as gasPrice might be set to 0.

Next we define the limit for the native resource as:
  `nativeLimit := gasLimit * nativePerGas`
```
