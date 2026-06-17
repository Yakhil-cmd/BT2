Now I have a complete picture of the vulnerability chain. Let me trace the full path:

1. `get_gas_price` in `gas_helpers.rs` (line 468): when `base_fee == 0`, returns `U256::ZERO` regardless of priority fee
2. `validation_impl.rs` (line 135): `native_per_gas = gas_price.div_ceil(native_price) = 0`
3. `validation_impl.rs` (line 196): `create_resources_for_tx` called with `free_native = (native_per_gas == 0) = true`
4. `gas_helpers.rs` (line 345): `native_limit = u64::MAX - 1` (capped at `MAX_NATIVE_COMPUTATIONAL`)
5. `refund_calculation.rs` (line 69): `delta_gas = 0` when `native_per_gas == 0` — no extra gas charged for native consumption

This is a complete, reachable chain. The analog is valid.

---

### Title
Priority Fee Silently Discarded When `base_fee == 0` Grants ZK Transactions `MAX_NATIVE_COMPUTATIONAL` Native Resources at Zero Cost — (File: `basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs`)

### Summary
When the block's EIP-1559 base fee is zero, `get_gas_price` unconditionally returns `U256::ZERO`, discarding any priority fee the sender set. This propagates to `native_per_gas = 0`, which triggers the `free_native` path in `create_resources_for_tx`, granting the transaction `MAX_NATIVE_COMPUTATIONAL` native resources at zero cost. The `deltaGas` adjustment is also suppressed, so no extra gas is charged to compensate the operator for proving work. This creates a "wait and benefit" dynamic: rational users are incentivized to delay computationally expensive ZK transactions until `base_fee` drops to zero, at which point they execute them for free while the operator bears the full proving cost.

### Finding Description

**Root cause — `get_gas_price` in `gas_helpers.rs`:**

```rust
// If base fee is zero, then we ignore priority fee
if base_fee.is_zero() {
    Ok(U256::ZERO)   // priority fee completely discarded
}
``` [1](#0-0) 

This is called from `zk/validation_impl.rs` for all non-service ZK transactions:

```rust
let gas_price = if transaction.is_service() {
    U256::ZERO
} else {
    get_gas_price::<S, Config>(system, transaction.max_fee_per_gas(), transaction.max_priority_fee_per_gas())?
};
``` [2](#0-1) 

The resulting `gas_price = 0` propagates to `native_per_gas = 0`:

```rust
} else {
    u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(...)
    // 0.div_ceil(native_price) = 0
}
``` [3](#0-2) 

`native_per_gas == 0` is passed as `free_native = true` to `create_resources_for_tx`:

```rust
let tx_resources = create_resources_for_tx::<S, L2ResourcesPolicy>(
    system,
    tx_gas_limit,
    native_per_gas == 0,   // free_native = true
    ...
``` [4](#0-3) 

Inside `create_resources_for_tx`, `free_native = true` sets the native limit to `u64::MAX - 1` (effectively `MAX_NATIVE_COMPUTATIONAL` after the cap):

```rust
// Note: for zero gas price, we use "unlimited native"
let native_limit = if cfg!(feature = "unlimited_native") || free_native {
    u64::MAX - 1
} else {
    native_prepaid_from_gas
};
``` [5](#0-4) 

Finally, in `compute_gas_refund`, the `deltaGas` adjustment is suppressed when `native_per_gas == 0`, so no extra gas is charged to the user to compensate the operator for native resource consumption:

```rust
let delta_gas = if native_per_gas == 0 {
    0   // no deltaGas adjustment — operator gets nothing for proving work
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};
``` [6](#0-5) 

**Asymmetry with Ethereum transactions:** For Ethereum-format transactions, `get_gas_prices` in `ethereum/validation_impl.rs` correctly uses the priority fee when `base_fee = 0` (`effective_gas_price = 0 + priority_fee_per_gas`). The bug is exclusive to ZK transactions routed through `get_gas_price` in `gas_helpers.rs`. [7](#0-6) 

### Impact Explanation

When `base_fee == 0`:

1. **Zero fee charged**: `fee_to_prepay = gas_price * gas_limit = 0 * gas_limit = 0`. The sender pays nothing.
2. **Maximum native resources granted for free**: `native_limit` is set to `MAX_NATIVE_COMPUTATIONAL` — the maximum computational native budget any transaction can receive.
3. **No deltaGas compensation**: `delta_gas = 0` regardless of actual native consumption, so the operator receives no gas-denominated compensation for the proving work performed.
4. **Operator financial loss**: The operator must prove the transaction (real RISC-V cycle cost) but receives zero fee revenue.
5. **Economic incentive misalignment**: Users are incentivized to delay computationally expensive ZK transactions until `base_fee` drops to zero, at which point they can execute them at maximum native resource budget for free — a direct "wait and benefit" dynamic.

### Likelihood Explanation

The operator sets `base_fee` as part of the block context. In a ZK rollup, `base_fee` can legitimately be set to zero during low-demand periods or as a deliberate policy to attract users. The vulnerability is deterministic: every ZK transaction submitted in a block with `base_fee == 0` receives `MAX_NATIVE_COMPUTATIONAL` native resources at zero cost. No special attacker capability is required beyond submitting a standard ZK transaction.

### Recommendation

When `base_fee == 0`, the priority fee should still be used as the effective gas price, consistent with how `get_gas_prices` handles Ethereum transactions. Replace the early-return in `get_gas_price`:

```rust
// Current (broken for ZK txs):
if base_fee.is_zero() {
    Ok(U256::ZERO)
}

// Fixed: mirror ethereum/validation_impl.rs behavior
if base_fee.is_zero() {
    let priority = max_priority_fee_per_gas.unwrap_or(max_fee_per_gas);
    Ok(priority.min(max_fee_per_gas))
}
```

This ensures that:
1. Users can pay a priority fee to compensate the operator for proving work even when `base_fee = 0`.
2. `native_per_gas > 0` when a priority fee is set, so native resources are properly priced.
3. The `deltaGas` mechanism correctly charges users for native resource consumption.
4. There is no economic incentive to delay transactions until `base_fee = 0`.

### Proof of Concept

```
Block context: base_fee = 0, native_price = 1000

ZK transaction:
  max_fee_per_gas        = 5000
  max_priority_fee_per_gas = 5000
  gas_limit              = 1_000_000

Step 1: get_gas_price → base_fee.is_zero() → returns U256::ZERO
        (priority fee of 5000 is silently discarded)

Step 2: native_per_gas = 0.div_ceil(1000) = 0

Step 3: create_resources_for_tx(free_native = true)
        → native_limit = u64::MAX - 1
        → capped to MAX_NATIVE_COMPUTATIONAL

Step 4: fee_to_prepay = 0 * 1_000_000 = 0  (sender pays nothing)

Step 5: compute_gas_refund: delta_gas = 0
        → operator receives 0 tokens regardless of native consumed

Result: Transaction executes with MAX_NATIVE_COMPUTATIONAL native resources
        at zero cost. Operator proves the block and receives nothing.

Contrast: same transaction with base_fee = 1 would compute
        gas_price = 1 + min(4999, 4999) = 5000
        native_per_gas = 5000/1000 = 5
        native_limit = 1_000_000 * 5 = 5_000_000 (bounded by MAX_NATIVE_COMPUTATIONAL)
        fee_to_prepay = 5000 * 1_000_000 = 5_000_000_000
        → operator is compensated; user has incentive to act now rather than wait.
```

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L344-349)
```rust
    // Note: for zero gas price, we use "unlimited native"
    let native_limit = if cfg!(feature = "unlimited_native") || free_native {
        u64::MAX - 1 // So any saturation below can not be subtracted from it
    } else {
        native_prepaid_from_gas
    };
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L466-470)
```rust
    let base_fee = system.get_eip1559_basefee();
    // If base fee is zero, then we ignore priority fee
    if base_fee.is_zero() {
        Ok(U256::ZERO)
    } else {
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L109-119)
```rust
    let gas_price = if transaction.is_service() {
        // Service transactions do not pay gas fees,
        // their gas price is allowed to be < block base fee.
        U256::ZERO
    } else {
        get_gas_price::<S, Config>(
            system,
            transaction.max_fee_per_gas(),
            transaction.max_priority_fee_per_gas(),
        )?
    };
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L134-138)
```rust
        } else {
            u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(TxError::Validation(
                InvalidTransaction::NativeResourcesAreTooExpensive,
            ))?
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L193-202)
```rust
    let tx_resources = create_resources_for_tx::<S, L2ResourcesPolicy>(
        system,
        tx_gas_limit,
        native_per_gas == 0,
        native_prepaid_from_gas,
        native_per_pubdata,
        intrinsic_gas,
        intrinsic_computational_native,
        intrinsic_pubdata,
    )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-73)
```rust
        let delta_gas = if native_per_gas == 0 {
            0
        } else {
            (native_used / native_per_gas) as i64 - (gas_used as i64)
        };
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L80-92)
```rust
    let base_fee = system.get_eip1559_basefee();
    let (max_fee_minus_base_fee, uf) = max_fee_per_gas.overflowing_sub(base_fee);
    require!(
        uf == false,
        TxError::Validation(InvalidTransaction::BaseFeeGreaterThanMaxFee,),
        system
    )?;

    let priority_fee_per_gas = core::cmp::min(*max_priority_fee_per_gas, max_fee_minus_base_fee);

    let effective_gas_price = base_fee + priority_fee_per_gas;

    Ok((effective_gas_price, priority_fee_per_gas))
```
