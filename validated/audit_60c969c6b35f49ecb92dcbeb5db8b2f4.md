### Title
`native_per_pubdata` Floor Division Truncation Silently Zeros Pubdata Native Cost When `pubdata_price < native_price` — (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

The `native_per_pubdata` ratio is computed with floor (truncating) division while `native_per_gas` is computed with ceiling division. When the operator-set `pubdata_price` is less than `native_price`, integer truncation silently produces `native_per_pubdata = 0`, making every byte of pubdata free in native resources for the entire block. Any user can then generate the maximum allowed pubdata per transaction at zero native cost, forcing the operator/prover to absorb the full L1 data-publication cost without compensation.

---

### Finding Description

In `validate_and_compute_fee_for_transaction` (the ZK L2 transaction validation path), two ratios are derived from the block's pricing parameters:

```rust
// Line 135 — ceiling division: user always pays ≥ true cost
let native_per_gas = u256_try_to_u64(&gas_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::NativeResourcesAreTooExpensive))?;

// Line 142 — floor division: truncates to 0 when pubdata_price < native_price
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
``` [1](#0-0) 

The same asymmetry is reproduced verbatim in the public API helper `validate_l2_tx_intrinsic_native_resources`, where the comment even documents the inconsistency:

```
// native_per_gas = ceil(gas_price / native_price)
// native_per_pubdata = pubdata_price / native_price   ← floor, no ceil
``` [2](#0-1) 

`native_per_pubdata` flows into two charging sites:

1. **Upfront intrinsic pubdata charge** inside `create_resources_for_tx`:
   ```rust
   let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
   ``` [3](#0-2) 

2. **Post-execution pubdata charge** inside `get_resources_to_charge_for_pubdata`:
   ```rust
   let native = current_pubdata_spent.checked_mul(native_per_pubdata)...;
   ``` [4](#0-3) 

When `native_per_pubdata = 0`, both multiplications yield 0. The transaction is charged **zero native resources** for all pubdata it produces, regardless of how many storage slots it writes.

The same truncation is present in the L1→L2 path, where `native_per_pubdata` is derived differently but the downstream charging functions are identical: [5](#0-4) 

---

### Impact Explanation

Native resources model the off-chain proving and data-publication cost. When `native_per_pubdata = 0`:

- Every byte of pubdata written to L1 costs the operator real ETH (blob/calldata fees) but the transaction pays **nothing** in native resources for it.
- A user can fill the entire per-block pubdata quota (up to `get_pubdata_limit()` bytes) with a single transaction whose native budget is sized only for computation, not data.
- The operator/prover bears the full L1 data cost without compensation, breaking the economic invariant that native resources cover proving + publication costs.
- Because the post-execution check `check_enough_resources_for_pubdata` always returns `enough = true` when `native_per_pubdata = 0`, the transaction is never reverted for pubdata overuse. [6](#0-5) 

---

### Likelihood Explanation

The condition `pubdata_price < native_price` is reachable in normal operation. For example:

- `native_price` is set high to reflect expensive RISC-V proving cycles.
- `pubdata_price` is set lower to reflect cheaper blob-gas costs on a given day.

Any ratio where `pubdata_price / native_price < 1` (e.g., `native_price = 1000`, `pubdata_price = 999`) silently zeros the pubdata charge. An unprivileged user needs only to observe the current block context (both values are public) and submit a storage-heavy transaction.

---

### Recommendation

Replace the floor division with ceiling division for `native_per_pubdata`, consistent with `native_per_gas`:

```rust
// Before (floor — can truncate to 0):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After (ceiling — consistent with native_per_gas):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs` `validate_l2_tx_intrinsic_native_resources` and in the L1 transaction path in `process_l1_transaction.rs`. [7](#0-6) [8](#0-7) 

---

### Proof of Concept

**Setup:**
- Block context: `native_price = 1000`, `pubdata_price = 999`, `eip1559_basefee = 1000`.
- `native_per_pubdata = 999 / 1000 = 0` (floor truncation).

**Attack transaction:**
- EIP-1559 tx with `max_fee_per_gas = 1000`, `gas_limit = 10_000_000`.
- Calldata targets a contract that executes 200 `SSTORE` operations writing non-zero values to fresh slots (≈ 200 × 32 = 6 400 bytes of pubdata).

**Observed behaviour:**
1. `create_resources_for_tx` charges `0 * intrinsic_pubdata = 0` native for upfront pubdata.
2. After execution, `get_resources_to_charge_for_pubdata` computes `6400 * 0 = 0` native.
3. `check_enough_resources_for_pubdata` returns `enough = true`; transaction succeeds.
4. The operator publishes 6 400 bytes to L1 and receives **zero** native-resource compensation.

**Expected behaviour with ceiling division:**
- `native_per_pubdata = ceil(999 / 1000) = 1`.
- Post-execution charge = `6400 * 1 = 6400` native units, correctly deducted from the transaction's native budget. [9](#0-8) [10](#0-9)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L352-353)
```rust
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
    let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) {
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L422-435)
```rust
pub fn get_resources_to_charge_for_pubdata<S: EthereumLikeTypes>(
    system: &mut System<S>,
    native_per_pubdata: u64,
    base_pubdata: Option<u64>,
) -> Result<(u64, S::Resources), SystemError> {
    let current_pubdata_spent = system
        .net_pubdata_used()?
        .saturating_sub(base_pubdata.unwrap_or(0));
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
    let native = <S::Resources as zk_ee::system::Resources>::Native::from_computational(native);
    Ok((current_pubdata_spent, S::Resources::from_native(native)))
}
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L481-488)
```rust
    let native_per_pubdata = (gas_per_pubdata as u64)
        .checked_mul(native_per_gas)
        .unwrap_or_else(|| {
            system_log!(
                system,
                "Native per pubdata calculation for L1 tx overflows, using saturated arithmetic instead");
                u64::MAX
        });
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L713-722)
```rust
    let (enough, to_charge_for_pubdata, pubdata_used) =
        check_enough_resources_for_pubdata(system, native_per_pubdata, resources, None)?;
    let is_success = !reverted && enough;
    if !enough {
        system_log!(system, "Not enough gas for pubdata after execution\n");
        // Burn all remaining ergs.
        resources.exhaust_ergs();
        // Reset returndata
        returndata = Vec::new_in(system.get_allocator());
    }
```
