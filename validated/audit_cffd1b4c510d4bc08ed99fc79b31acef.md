### Title
`native_per_pubdata` Truncates to Zero via Integer Division, Allowing Free Pubdata Consumption - (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

`native_per_pubdata` is computed with truncating integer division (`wrapping_div`) instead of ceiling division (`div_ceil`). When `pubdata_price < native_price`, the result is `0`, making all pubdata consumption free in native resources. Any unprivileged transaction sender can then produce unlimited pubdata without paying the corresponding native resource cost, causing the operator to bear L1 data-availability costs uncompensated.

---

### Finding Description

In `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`, the two per-unit native resource rates are computed as follows:

```rust
// native_per_gas uses div_ceil (rounds UP — correct)
u256_try_to_u64(&gas_price.div_ceil(native_price))...

// native_per_pubdata uses wrapping_div (truncates — WRONG)
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
``` [1](#0-0) 

`native_per_gas` correctly uses `div_ceil` to round up, ensuring at least 1 native unit is charged per gas unit when the ratio is non-zero. `native_per_pubdata` uses `wrapping_div`, which truncates toward zero. Whenever `pubdata_price < native_price`, the result is `0`.

The same truncating division is replicated in the public API helper:

```rust
// api/src/helpers.rs line 427
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
``` [2](#0-1) 

When `native_per_pubdata == 0`, every downstream pubdata-cost calculation collapses to zero:

1. **Intrinsic pubdata overhead** in `create_resources_for_tx`:
   `intrinsic_pubdata_overhead = native_per_pubdata.saturating_mul(intrinsic_pubdata) = 0` [3](#0-2) 

2. **Runtime pubdata charge** in `get_resources_to_charge_for_pubdata`:
   `native = current_pubdata_spent.checked_mul(0) = 0` [4](#0-3) 

3. **Post-execution pubdata check** in `check_enough_resources_for_pubdata` always passes because `resources_for_pubdata` is zero. [5](#0-4) 

The block metadata structure confirms that `pubdata_price` and `native_price` are independent operator-supplied values with no enforced ordering constraint:

```rust
pub struct BlockMetadataFromOracle {
    pub pubdata_price: U256,
    pub native_price: U256,
    ...
}
``` [6](#0-5) 

The test default already demonstrates a configuration where `pubdata_price = 0` and `native_price = 10`, confirming the condition is reachable in practice: [7](#0-6) 

---

### Impact Explanation

When `pubdata_price < native_price` (e.g., `pubdata_price = 5`, `native_price = 10`), `native_per_pubdata` truncates to `0`. A transaction sender can then:

- Write to arbitrarily many storage slots (each producing a state-diff pubdata entry)
- Emit arbitrarily many logs
- Deploy large contracts

…all without consuming any native resources for the pubdata produced. The operator must still pay L1 data-availability costs for every byte published, but receives no native-resource compensation from the transaction fee. This is a direct, repeatable funds-loss path for the operator/protocol, exploitable by any unprivileged L2 transaction sender whenever the operator sets `pubdata_price < native_price`.

---

### Likelihood Explanation

The condition `pubdata_price < native_price` is realistic and not prevented by any validation. `pubdata_price` tracks L1 blob/calldata costs (denominated in wei per byte) while `native_price` tracks proving cost (denominated in wei per RISC-V cycle). These are independent market-driven quantities. During periods of low L1 data costs or high proving costs, `pubdata_price < native_price` is a normal operating condition. The test harness itself ships with `pubdata_price = 0`, confirming the developers did not treat this as an error state.

---

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata`, mirroring the treatment of `native_per_gas`:

```rust
// Before (truncates to 0 when pubdata_price < native_price):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;

// After (rounds up, ensuring at least 1 native unit when pubdata_price > 0):
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs` line 427. [8](#0-7) [9](#0-8) 

---

### Proof of Concept

**Setup:** Block metadata with `pubdata_price = 5`, `native_price = 10` (a realistic low-L1-cost scenario).

**Calculation:**
```
native_per_pubdata = pubdata_price.wrapping_div(native_price)
                   = 5 / 10
                   = 0   ← truncated to zero
```

**Effect in `get_resources_to_charge_for_pubdata`:**
```
native = current_pubdata_spent * native_per_pubdata
       = 1_000_000 * 0
       = 0
```

A transaction that writes to 10,000 storage slots (producing ~320,000 bytes of pubdata) passes `check_enough_resources_for_pubdata` with zero native resource charge. The operator publishes 320,000 bytes to L1 at their own cost. The attacker pays only EVM gas for the SSTORE opcodes, not the L1 data-availability cost.

With `div_ceil`, the same scenario yields:
```
native_per_pubdata = ceil(5 / 10) = 1
native = 1_000_000 * 1 = 1_000_000  ← correctly charged
```

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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L451-455)
```rust
    let (pubdata_used, resources_for_pubdata) =
        get_resources_to_charge_for_pubdata(system, native_per_pubdata, base_pubdata)?;
    system_log!(system, "Checking gas for pubdata, resources_for_pubdata: {resources_for_pubdata:?}, resources: {resources:?}\n");
    let enough = resources.has_enough(&resources_for_pubdata);
    Ok((enough, resources_for_pubdata, pubdata_used))
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L123-125)
```rust
    pub pubdata_price: U256,
    pub native_price: U256,
    pub coinbase: B160,
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L208-211)
```rust
            eip1559_basefee: U256::from(1000u64),
            pubdata_price: U256::from(0u64),
            native_price: U256::from(10),
            block_number: 1,
```
