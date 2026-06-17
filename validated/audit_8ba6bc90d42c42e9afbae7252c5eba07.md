### Title
Integer Truncation in `native_per_pubdata` Calculation Causes Zero Pubdata Native Cost - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

### Summary

`native_per_pubdata` is computed via floor (`wrapping_div`) division while `native_per_gas` uses ceiling (`div_ceil`) division. When `pubdata_price < native_price`, `native_per_pubdata` truncates to 0, making pubdata completely free in native resources for every transaction in that block.

### Finding Description

In `validate_and_compute_fee_for_transaction`, the two key resource ratios are computed as follows:

```rust
// Line 135 — ceiling division, conservative
let native_per_gas = u256_try_to_u64(&gas_price.div_ceil(native_price))...

// Line 142 — floor division, NOT conservative
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
``` [1](#0-0) 

Whenever `pubdata_price < native_price` (e.g., `pubdata_price = native_price - 1`), `wrapping_div` yields 0. The same truncation exists in the API-layer helper:

```rust
// api/src/helpers.rs line 427
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
``` [2](#0-1) 

With `native_per_pubdata = 0`, two downstream charging sites both produce zero cost:

1. **Intrinsic pubdata overhead** in `create_resources_for_tx`:
   ```rust
   let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata); // = 0
   ``` [3](#0-2) 

2. **Execution pubdata charge** in `get_resources_to_charge_for_pubdata`:
   ```rust
   let native = current_pubdata_spent.checked_mul(native_per_pubdata); // = 0
   ``` [4](#0-3) 

`check_enough_resources_for_pubdata` then always passes (0 native required ≤ any remaining native), so the transaction is never reverted for pubdata over-consumption. [5](#0-4) 

The same `native_per_pubdata` flows into the L1-transaction path via `check_enough_resources_for_pubdata` called from `execute_l1_tx_body`: [6](#0-5) 

### Impact Explanation

When `pubdata_price < native_price`, every transaction in the block pays **zero native resources** for all pubdata it writes. An unprivileged sender can craft transactions that write the maximum allowed pubdata (bounded only by the block-level `pubdata_limit`) without any native resource cost. This breaks the double-resource accounting invariant: EVM gas is charged correctly, but the native (proving-cost) dimension of pubdata is silently zeroed out. The operator loses all pubdata-derived native revenue, and the prover bears the full cost of proving the extra state diffs without compensation.

### Likelihood Explanation

The condition `pubdata_price < native_price` is realistic. The operator sets both values independently. Any configuration where `pubdata_price` is set below `native_price` (e.g., to subsidize pubdata, or during a price-ratio transition) silently activates the bug for all transactions in every affected block. No special privilege is required by the attacker — any standard L2 EIP-1559 transaction triggers the path.

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata`, consistent with how `native_per_gas` is computed:

```rust
// Before (truncates to 0 when pubdata_price < native_price)
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))...

// After (rounds up, conservative — never undercharges)
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))...
```

Apply the same fix in `api/src/helpers.rs` line 427. [7](#0-6) [2](#0-1) 

### Proof of Concept

1. Operator sets `pubdata_price = native_price - 1` (e.g., `pubdata_price = 9`, `native_price = 10`).
2. `native_per_pubdata = 9.wrapping_div(10) = 0`.
3. Attacker submits an L2 EIP-1559 transaction calling a contract that writes 20 storage slots (≈ 640 bytes of pubdata).
4. `get_resources_to_charge_for_pubdata` returns `(640, Resources::from_native(0))`.
5. `check_enough_resources_for_pubdata` returns `enough = true` regardless of remaining native.
6. Transaction succeeds; attacker paid EVM gas for the SSTOREs but **zero native resources** for the 640 bytes of pubdata, which the prover must still prove and publish.

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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L445-455)
```rust
pub fn check_enough_resources_for_pubdata<S: EthereumLikeTypes>(
    system: &mut System<S>,
    native_per_pubdata: u64,
    resources: &S::Resources,
    base_pubdata: Option<u64>,
) -> Result<(bool, S::Resources, u64), SystemError> {
    let (pubdata_used, resources_for_pubdata) =
        get_resources_to_charge_for_pubdata(system, native_per_pubdata, base_pubdata)?;
    system_log!(system, "Checking gas for pubdata, resources_for_pubdata: {resources_for_pubdata:?}, resources: {resources:?}\n");
    let enough = resources.has_enough(&resources_for_pubdata);
    Ok((enough, resources_for_pubdata, pubdata_used))
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L713-715)
```rust
    let (enough, to_charge_for_pubdata, pubdata_used) =
        check_enough_resources_for_pubdata(system, native_per_pubdata, resources, None)?;
    let is_success = !reverted && enough;
```
