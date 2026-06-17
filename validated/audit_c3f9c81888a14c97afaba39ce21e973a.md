### Title
Zero `gas_per_pubdata_limit` in L1→L2 Transactions Bypasses Pubdata Cost Accounting - (`File: basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

An L1→L2 priority transaction sender can set `gas_per_pubdata_limit = 0` in the transaction fields. ZKsync OS reads this value directly without enforcing a minimum bound, causing `native_per_pubdata` to be computed as zero. With a zero pubdata price, the post-execution pubdata resource check always passes and no native resources are deducted for any pubdata generated during execution. The user can write to many storage slots (generating pubdata up to the block limit) while paying only for computational gas, forcing the operator to bear the full L1 data-posting cost.

---

### Finding Description

In `process_l1_transaction.rs`, the `gas_per_pubdata_limit` field is read directly from the user-controlled ABI-encoded transaction:

```rust
let gas_per_pubdata = transaction.gas_per_pubdata_limit.read();
```

This value is then used to compute `native_per_pubdata` in `prepare_and_check_resources`:

```rust
let native_per_pubdata = (gas_per_pubdata as u64)
    .checked_mul(native_per_gas)
    .unwrap_or_else(|| { ... u64::MAX });
```

When `gas_per_pubdata = 0`, `native_per_pubdata = 0 * native_per_gas = 0` regardless of `native_per_gas`.

This zero value propagates into two critical places:

**1. `create_resources_for_tx` (gas_helpers.rs:352):**
```rust
let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
// = 0 * L1_TX_INTRINSIC_PUBDATA = 0
```
No native is deducted for intrinsic pubdata overhead, giving the user the full `native_prepaid_from_gas` budget for computation.

**2. `get_resources_to_charge_for_pubdata` (gas_helpers.rs:430-431):**
```rust
let native = current_pubdata_spent
    .checked_mul(native_per_pubdata)
    .ok_or(out_of_native_resources!())?;
// = pubdata_used * 0 = 0
```
The post-execution pubdata check (`check_enough_resources_for_pubdata`) always returns `true` because `resources_for_pubdata = 0`. In `compute_gas_refund`, `to_charge_for_pubdata = 0` is charged, so `gas_used` is computed purely from computational ergs, not pubdata. The user receives a larger refund while having generated significant pubdata.

There is no minimum-bound validation on `gas_per_pubdata_limit` anywhere in the ZKsync OS L1 transaction path. The `validate_structure` function in `abi_encoded/mod.rs` only checks that `gas_per_pubdata_limit != 0` for **non-L1** transaction types, explicitly leaving L1 transactions unchecked.

---

### Impact Explanation

An attacker submitting an L1→L2 priority transaction with `gas_per_pubdata_limit = 0` and `gas_price > 0` (to keep a finite native budget) can:

1. Execute SSTORE-heavy calldata that generates pubdata up to the block-level pubdata limit (`system.get_pubdata_limit()`).
2. Pay zero native resources for all generated pubdata — the post-execution check always passes.
3. Receive a full gas refund for unused computational gas, as if no pubdata was generated.
4. Force the operator to post all generated pubdata to L1 at the operator's expense.

This is a **resource accounting bug**: the user-controlled `gas_per_pubdata_limit = 0` acts as a divisor-like parameter that collapses the pubdata cost to zero, analogous to the original report's `_optionPrice = 1 wei` collapsing the per-token cost. The operator subsidizes the user's L1 data-availability costs.

---

### Likelihood Explanation

Any unprivileged L1→L2 transaction sender can set `gas_per_pubdata_limit = 0` when constructing the ABI-encoded transaction. No special access, leaked key, or governance majority is required. The L1 contracts are noted in the code comments as the intended enforcement point, but ZKsync OS itself performs no minimum check, making this directly exploitable by any user who submits an L1 priority transaction.

---

### Recommendation

Enforce a minimum value for `gas_per_pubdata_limit` in L1 transactions within `prepare_and_check_resources`. A reasonable minimum is the current block-level `pubdata_price / native_price` ratio (the same value used for L2 transactions), or a protocol-defined constant. If `gas_per_pubdata = 0` is detected, either reject the transaction (logging a system warning as done for other L1 validation edge cases) or substitute the block-level pubdata price:

```rust
let gas_per_pubdata = if gas_per_pubdata == 0 {
    system_log!(system, "L1 tx gas_per_pubdata is 0, using block pubdata price\n");
    // use block-level minimum or a protocol constant
    MIN_GAS_PER_PUBDATA
} else {
    gas_per_pubdata
};
```

---

### Proof of Concept

**Attack transaction parameters:**
- `gas_price = 10` (non-zero, so `native_per_gas = 1`, `free_native = false`)
- `gas_per_pubdata_limit = 0`
- `gas_limit = 1_000_000`
- Calldata: invokes a contract that performs 100+ SSTORE operations

**Trace through ZKsync OS:**

1. `gas_per_pubdata = transaction.gas_per_pubdata_limit.read()` → `0` [1](#0-0) 

2. `native_per_pubdata = (0u64).checked_mul(native_per_gas)` → `0` [2](#0-1) 

3. `intrinsic_pubdata_overhead = 0 * L1_TX_INTRINSIC_PUBDATA = 0` — full native budget preserved [3](#0-2) 

4. Post-execution: `native = pubdata_used * 0 = 0` → `has_enough = true` always [4](#0-3) 

5. `to_charge_for_pubdata = 0` passed to `compute_gas_refund` → `gas_used` reflects only computational gas, not pubdata [5](#0-4) 

6. No minimum check on `gas_per_pubdata_limit` exists in `validate_structure` for L1 tx types [6](#0-5) 

**Result:** The attacker generates pubdata (up to the block pubdata limit) at zero cost. The operator posts this pubdata to L1 at their own expense. The attacker receives a full refund as if no pubdata was generated.

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L80-80)
```rust
    let gas_per_pubdata = transaction.gas_per_pubdata_limit.read();
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

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L430-434)
```rust
    let native = current_pubdata_spent
        .checked_mul(native_per_pubdata)
        .ok_or(out_of_native_resources!())?;
    let native = <S::Resources as zk_ee::system::Resources>::Native::from_computational(native);
    Ok((current_pubdata_spent, S::Resources::from_native(native)))
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L29-33)
```rust
    resources.charge_unchecked(&to_charge_for_pubdata);

    let mut gas_used = gas_limit
        .checked_sub(resources.ergs().0.div_floor(ERGS_PER_GAS))
        .ok_or(internal_error!("gas remaining > gas limit"))?;
```

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L241-249)
```rust
        // gas_per_pubdata_limit should be zero for non L1 transactions
        match tx_type {
            Self::UPGRADE_TX_TYPE | Self::L1_L2_TX_TYPE => {}
            _ => {
                if self.gas_per_pubdata_limit.read() != 0 {
                    return Err(());
                }
            }
        }
```
