### Title
`native_per_pubdata` Truncates to Zero via Floor Division, Making Pubdata Free for All Transactions - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

### Summary

In ZKsync OS's ZK transaction validation path, `native_per_pubdata` is computed using integer floor division (`wrapping_div`). When `pubdata_price < native_price`, the result truncates to zero. This silently disables all pubdata charging for every transaction in the block, allowing any unprivileged sender to write unlimited pubdata at zero cost.

### Finding Description

In `validate_and_compute_fee_for_transaction`, the per-pubdata-byte native cost is computed as:

```rust
// basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs, line 142
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

`wrapping_div` is integer (floor) division. When `pubdata_price < native_price`, the result is `0`. There is no guard against a zero result. [1](#0-0) 

By contrast, `native_per_gas` uses **ceiling** division (`div_ceil`) to guarantee it is never rounded to zero:

```rust
// line 135
u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(...)
``` [2](#0-1) 

The same floor-division pattern is replicated in the public API helper:

```rust
// api/src/helpers.rs, line 427
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
``` [3](#0-2) 

When `native_per_pubdata == 0`, the downstream effects are:

1. **Intrinsic pubdata overhead is zero** — `create_resources_for_tx` computes `intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata)` = 0, so no native is deducted upfront. [4](#0-3) 

2. **Post-execution pubdata charge is zero** — `get_resources_to_charge_for_pubdata` computes `native = current_pubdata_spent.checked_mul(0)` = 0, so no native is charged for any pubdata written during execution. [5](#0-4) 

3. **`delta_gas` adjustment is zero** — `compute_gas_refund` computes `native_used / native_per_gas` but since pubdata cost zero native, `native_used` is only computational native, and the pubdata cost is never reflected in `gas_used`. [6](#0-5) 

### Impact Explanation

When `pubdata_price < native_price` (a valid operator configuration), every transaction in the block can write up to the block pubdata limit for free. The operator publishes this data to L1 and bears the full L1 data cost, but receives zero compensation in native tokens. Any user can exploit this by submitting storage-write-heavy transactions (e.g., writing to many distinct storage slots) with no additional fee cost beyond EVM gas.

This is a **resource accounting bug**: the protocol silently under-charges for a real cost (L1 data publication), causing a direct financial loss to the operator/protocol for every block where `pubdata_price < native_price`.

### Likelihood Explanation

The condition `pubdata_price < native_price` is a realistic operator configuration. `native_price` reflects the cost of a single RISC-V proving cycle, while `pubdata_price` reflects the cost of one byte of L1 calldata. These are independent quantities set by the operator via block metadata. On a chain where proving is expensive relative to L1 data costs, `native_price > pubdata_price` is entirely plausible. Any user submitting a transaction during such a block can exploit the zero pubdata charge.

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata`, consistent with how `native_per_gas` is computed:

```rust
// Before (floor division — can produce 0):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After (ceiling division — guarantees at least 1 when pubdata_price > 0):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs` line 427. Additionally, add an explicit check that `native_per_pubdata > 0` when `pubdata_price > 0` to make the invariant explicit.

### Proof of Concept

**Setup**: Operator sets `native_price = 1000`, `pubdata_price = 999` (a valid configuration where proving is slightly more expensive than pubdata).

**Computation**:
- `native_per_pubdata = 999.wrapping_div(1000) = 0` (floor division)

**Exploit**: Attacker submits a transaction that writes to 1000 distinct storage slots (generating ~32,000 bytes of pubdata). With `native_per_pubdata = 0`:
- `get_resources_to_charge_for_pubdata` returns `native = 32000 * 0 = 0`
- The transaction pays only EVM gas for the storage writes, not for the pubdata
- The operator publishes 32,000 bytes to L1 and receives zero pubdata compensation

**Contrast with correct behavior**: With `div_ceil`, `native_per_pubdata = ceil(999/1000) = 1`, and the transaction would be charged `32000 * 1 = 32000` native units for pubdata. [7](#0-6) [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L134-138)
```rust
        } else {
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L141-144)
```rust
    // We checked native_price != 0 above
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
        .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
    let native_prepaid_from_gas = native_per_gas.saturating_mul(tx_gas_limit);
```

**File:** api/src/helpers.rs (L426-428)
```rust
    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;

```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L344-359)
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L430-434)
```rust
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
    let native = <S::Resources as zk_ee::system::Resources>::Native::from_computational(native);
    Ok((current_pubdata_spent, S::Resources::from_native(native)))
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
