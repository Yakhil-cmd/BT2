### Title
Integer Division Truncation in `native_per_pubdata` Calculation Allows Transactions to Write Unlimited Pubdata Without Native Resource Charges - (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

---

### Summary

When `pubdata_price < native_price`, the floor division used to compute `native_per_pubdata` truncates to zero. Because all pubdata charging is gated on this value, a transaction can write arbitrarily large amounts of pubdata without consuming any native resources for it, while still executing within its EVM gas budget. The operator bears the L1 data-posting cost without compensation.

---

### Finding Description

In `validation_impl.rs`, `native_per_gas` is computed with **ceiling** division to protect the operator from undercharging:

```rust
// validation_impl.rs:135
u256_try_to_u64(&gas_price.div_ceil(native_price))
```

But `native_per_pubdata` is computed with **floor** division (`wrapping_div`):

```rust
// validation_impl.rs:142-143
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

When `pubdata_price < native_price` (e.g., `pubdata_price = 5`, `native_price = 10`):

```
native_per_pubdata = 5 / 10 = 0  (floor division)
```

This zero propagates through every pubdata-charging site:

1. **Intrinsic pubdata overhead** (`gas_helpers.rs:352`):
   ```rust
   let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
   // = 0 * intrinsic_pubdata = 0  → no native deducted at tx start
   ```

2. **Post-execution pubdata charge** (`gas_helpers.rs:430-432`):
   ```rust
   let native = current_pubdata_spent
       .checked_mul(native_per_pubdata)  // = pubdata_bytes * 0 = 0
       .ok_or(out_of_native_resources!())?;
   ```

3. **`check_enough_resources_for_pubdata`** always returns `enough = true` since 0 native is required.

4. **`deltaGas` adjustment** (`refund_calculation.rs:72`):
   ```rust
   (native_used / native_per_gas) as i64 - (gas_used as i64)
   ```
   Since pubdata native cost is zero, `native_used` does not grow with pubdata, so no extra gas is charged to the sender.

**Concrete example:**
- Block: `native_price = 10`, `pubdata_price = 9` → `native_per_pubdata = 0`
- Attacker submits a transaction that writes 1,000 storage slots (generating ~32,000 bytes of pubdata)
- Pubdata native cost charged: `32,000 * 0 = 0`
- Attacker pays only for EVM gas (SSTORE opcodes), not for the L1 data-posting cost
- The operator must post 32,000 bytes to L1 without receiving native resource compensation

The same asymmetric floor division appears in `api/src/helpers.rs:427`:
```rust
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

---

### Impact Explanation

**Resource accounting bug / operator funds loss path.** Pubdata is the dominant cost in a ZK rollup — it is posted to L1 (Ethereum calldata or blobs). The native resource system is specifically designed to ensure transactions pay for their pubdata footprint. When `native_per_pubdata = 0`, this invariant is broken: transactions can write unbounded pubdata (limited only by EVM gas for SSTORE/LOG opcodes) without any native resource constraint. The operator bears the L1 data-posting cost without being compensated through the fee mechanism. This is a direct loss of operator funds proportional to the pubdata written.

---

### Likelihood Explanation

The condition `pubdata_price < native_price` is realistic and can occur during normal operation. The test fixture `BlockMetadataFromOracle::new_for_test()` uses `pubdata_price = 0` and `native_price = 10`, and the test `test_check_pubdata_has_timestamp` uses `native_price = 100, pubdata_price = 2` — both produce `native_per_pubdata = 0`. Any unprivileged L2 transaction sender can exploit this whenever the block's pricing satisfies `pubdata_price < native_price`, with no special access required.

---

### Recommendation

Replace `wrapping_div` with `div_ceil` for `native_per_pubdata`, consistent with how `native_per_gas` is computed:

```rust
// validation_impl.rs:142
let native_per_pubdata = u256_try_to_u64(&pubdata_price.div_ceil(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

Apply the same fix in `api/src/helpers.rs:427`. This ensures that even when `pubdata_price` is fractionally smaller than `native_price`, at least 1 native unit is charged per pubdata byte, preventing free pubdata writes.

---

### Proof of Concept

1. Operator sets block context: `native_price = 10`, `pubdata_price = 9`.
2. `native_per_pubdata = 9.wrapping_div(10) = 0`.
3. Attacker submits an L2 transaction calling a contract that executes 100 `SSTORE` operations to fresh slots (each SSTORE costs 20,000 EVM gas; 100 × 20,000 = 2,000,000 gas, within a typical gas limit).
4. Each SSTORE generates 32 bytes of pubdata key + ~32 bytes of value diff = ~6,400 bytes total pubdata.
5. `get_resources_to_charge_for_pubdata` computes `native = 6400 * 0 = 0`.
6. `check_enough_resources_for_pubdata` returns `enough = true`.
7. Transaction succeeds; attacker pays only for EVM gas. Operator must post 6,400 bytes to L1 at their own expense.
8. Repeat with any number of transactions; each one writes pubdata for free in native resource terms.

**Affected files:**
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L141-143)
```rust
    // We checked native_price != 0 above
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
        .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

**File:** api/src/helpers.rs (L426-427)
```rust
    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L430-432)
```rust
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-73)
```rust
        let delta_gas = if native_per_gas == 0 {
            0
        } else {
            (native_used / native_per_gas) as i64 - (gas_used as i64)
        };
```
