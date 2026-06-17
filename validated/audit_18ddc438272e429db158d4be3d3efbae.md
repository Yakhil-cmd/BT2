### Title
`get_gas_price()` Returns Zero When `base_fee == 0`, Causing Incorrect `native_per_gas` and Unlimited Native Resource Allocation for ZKsync L2 Transactions — (`File: basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs`)

---

### Summary

`get_gas_price()` in `gas_helpers.rs` performs an early return of `U256::ZERO` whenever `base_fee == 0`, completely discarding the caller-supplied `max_fee_per_gas` and `max_priority_fee_per_gas`. This is the structural analog of the `traderReferralDiscount()` bug: a zero-valued input causes the function to return a wrong primary value, which then propagates into multiple downstream computations — `native_per_gas`, `native_prepaid_from_gas`, `fee_to_prepay`, and the native resource budget — all of which become incorrect.

---

### Finding Description

**Root cause — `get_gas_price` in `gas_helpers.rs` lines 461–493:**

```rust
pub(crate) fn get_gas_price<S: EthereumLikeTypes, Config: BasicBootloaderExecutionConfig>(
    system: &mut System<S>,
    max_fee_per_gas: &U256,
    max_priority_fee_per_gas: Option<&U256>,
) -> Result<U256, TxError> {
    let base_fee = system.get_eip1559_basefee();
    // If base fee is zero, then we ignore priority fee
    if base_fee.is_zero() {
        Ok(U256::ZERO)          // <-- early return, ignores max_fee_per_gas entirely
    } else {
        ...
        let gas_price = (base_fee.saturating_add(priority_fee_per_gas)).min(*max_fee_per_gas);
        Ok(gas_price)
    }
}
``` [1](#0-0) 

When `base_fee == 0`, the EIP-1559 formula still yields a non-zero effective gas price if the user set a priority fee: `effective_gas_price = min(max_fee_per_gas, 0 + max_priority_fee_per_gas) = priority_fee_per_gas`. The function ignores this and returns `U256::ZERO`.

**Contrast with the Ethereum flow's `get_gas_prices`** (used for RLP-encoded Ethereum transactions), which correctly handles `base_fee == 0`:

```rust
let priority_fee_per_gas = core::cmp::min(*max_priority_fee_per_gas, max_fee_minus_base_fee);
let effective_gas_price = base_fee + priority_fee_per_gas;  // = priority_fee when base_fee=0
``` [2](#0-1) 

**Propagation chain in `zk/validation_impl.rs`:**

`gas_price = 0` flows into:

1. `native_per_gas = gas_price.div_ceil(native_price) = 0` (line 135)
2. `native_prepaid_from_gas = 0 * tx_gas_limit = 0` (line 144)
3. `create_resources_for_tx` called with `native_per_gas == 0` → `true` (unlimited native flag, line 196)
4. `gas_fee_amount = 0 * tx_gas_limit = 0` → `fee_to_prepay = 0` (lines 460–491) [3](#0-2) [4](#0-3) [5](#0-4) 

**In `compute_gas_refund` (`refund_calculation.rs`):**

```rust
let full_native_limit = if cfg!(feature = "unlimited_native") || native_per_gas == 0 {
    u64::MAX - 1          // unlimited native budget
} else { ... };

let delta_gas = if native_per_gas == 0 {
    0                     // no native-to-gas adjustment
} else { ... };
``` [6](#0-5) 

**Operator payment in `zk/mod.rs`:**

```rust
let token_to_pay_operator = U256::from(context.gas_used)
    .checked_mul(gas_price_for_operator)  // gas_price = 0 → operator gets 0
    .ok_or(internal_error!("gu*gpfo"))?;
``` [7](#0-6) 

---

### Impact Explanation

When `base_fee == 0`, any ZKsync L2 (non-service, non-Ethereum-RLP) transaction:

1. **Pays zero fee** regardless of `max_fee_per_gas` or `max_priority_fee_per_gas` — `fee_to_prepay = 0`.
2. **Operator receives zero fee** — `token_to_pay_operator = 0`, even if the user declared willingness to pay a priority fee.
3. **Gets unlimited native resources** — `full_native_limit = u64::MAX - 1`, bypassing the native resource budget that normally bounds RISC-V cycle consumption.
4. **No `delta_gas` adjustment** — native resource consumption does not translate into additional gas charges, breaking the double-resource accounting invariant described in `docs/double_resource_accounting.md`.

This is a resource accounting bug with a direct operator funds-loss path: fees that should flow to the sequencer/operator are silently zeroed out.

---

### Likelihood Explanation

`base_fee == 0` is an explicitly tested and supported scenario in ZKsync OS. The test `test_gas_price_zero_fee_zero` sets `eip1559_basefee: U256::ZERO` and exercises this path. The base fee is set by the operator/sequencer in the block context; it can be zero during network initialization, in test/staging environments, or when the operator deliberately sets it to zero. Any unprivileged user who submits a ZKsync L2 transaction during such a period triggers the bug automatically — no special permissions or knowledge required beyond knowing the current base fee is zero. [8](#0-7) 

---

### Recommendation

Remove the early-return branch. When `base_fee == 0`, the EIP-1559 formula still applies and should return `min(max_fee_per_gas, max_priority_fee_per_gas)`. The existing `else` branch already computes this correctly for non-zero `base_fee`; it should be used unconditionally:

```rust
pub(crate) fn get_gas_price<...>(...) -> Result<U256, TxError> {
    let base_fee = system.get_eip1559_basefee();
    // Remove the early-return: let the general formula handle base_fee == 0
    let max_priority_fee_per_gas = max_priority_fee_per_gas.unwrap_or(max_fee_per_gas);
    require!(max_priority_fee_per_gas <= max_fee_per_gas, ...)?;
    if !Config::SIMULATION {
        require!(&base_fee <= max_fee_per_gas, ...)?;
    }
    let priority_fee_per_gas =
        (*max_priority_fee_per_gas).min(max_fee_per_gas.saturating_sub(base_fee));
    let gas_price = (base_fee.saturating_add(priority_fee_per_gas)).min(*max_fee_per_gas);
    Ok(gas_price)
}
```

This aligns the ZKsync flow with the Ethereum flow's `get_gas_prices`, which already handles `base_fee == 0` correctly.

---

### Proof of Concept

1. Operator sets `eip1559_basefee = 0` in the block context (valid, tested scenario).
2. Attacker submits a ZKsync L2 EIP-1559 transaction with `max_fee_per_gas = 1000`, `max_priority_fee_per_gas = 500`, `gas_limit = 200_000`.
3. `get_gas_price` returns `U256::ZERO` (line 469).
4. `native_per_gas = 0` (line 135 of `zk/validation_impl.rs`).
5. `fee_to_prepay = 0` — user's balance is not debited for fees.
6. Transaction executes with `full_native_limit = u64::MAX - 1` (line 60 of `refund_calculation.rs`).
7. `token_to_pay_operator = 0` — operator receives nothing.
8. Correct behavior: `gas_price = min(1000, 500) = 500`; operator should receive `500 * gas_used`; native budget should be `500 / native_price * 200_000`. [9](#0-8) [10](#0-9) [11](#0-10) [7](#0-6)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L461-493)
```rust
pub(crate) fn get_gas_price<S: EthereumLikeTypes, Config: BasicBootloaderExecutionConfig>(
    system: &mut System<S>,
    max_fee_per_gas: &U256,
    max_priority_fee_per_gas: Option<&U256>,
) -> Result<U256, TxError> {
    let base_fee = system.get_eip1559_basefee();
    // If base fee is zero, then we ignore priority fee
    if base_fee.is_zero() {
        Ok(U256::ZERO)
    } else {
        let max_priority_fee_per_gas = max_priority_fee_per_gas.unwrap_or(max_fee_per_gas);
        require!(
            max_priority_fee_per_gas <= max_fee_per_gas,
            TxError::Validation(InvalidTransaction::PriorityFeeGreaterThanMaxFee,),
            system
        )?;
        if !Config::SIMULATION {
            // Skip this check on simulation
            require!(
                &base_fee <= max_fee_per_gas,
                TxError::Validation(InvalidTransaction::BaseFeeGreaterThanMaxFee,),
                system
            )?;
        }
        let priority_fee_per_gas =
            (*max_priority_fee_per_gas).min(max_fee_per_gas.saturating_sub(base_fee));
        // Normally, max_fee_per_gas >= base_fee + priority_fee_per_gas,
        // but we add this min to make it work in simulation too, where we do not
        // enforce max_fee_per_gas > base_fee.
        let gas_price = (base_fee.saturating_add(priority_fee_per_gas)).min(*max_fee_per_gas);
        Ok(gas_price)
    }
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L88-92)
```rust
    let priority_fee_per_gas = core::cmp::min(*max_priority_fee_per_gas, max_fee_minus_base_fee);

    let effective_gas_price = base_fee + priority_fee_per_gas;

    Ok((effective_gas_price, priority_fee_per_gas))
```

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L192-202)
```rust
    // Now we will materialize resources, from which we will try to charge intrinsic cost on top.
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L459-491)
```rust
    // But the fee to charge is based on current block context, and not worst case of max fee (backward-compatible manner)
    let gas_fee_amount = gas_price
        .checked_mul(U256::from(tx_gas_limit))
        .ok_or(internal_error!("gas price by tx gas limit"))?;

    // Note: no need to feature gate this part, as for non-EIP4844 transactions
    // num_blobs will be 0.
    let num_blobs = system.metadata.num_blobs();
    // NOTE: it's a special resource - not transaction gas. Will be used to charge fee only
    let blob_gas_used = num_blobs as u64 * GAS_PER_BLOB;
    let fee_for_blob_gas = if blob_gas_used > 0 {
        system_log!(
            system,
            "Blob gas price = {}\n",
            &system.get_blob_base_fee_per_gas()
        );

        let Some(value) = system
            .get_blob_base_fee_per_gas()
            .checked_mul(U256::from(blob_gas_used))
        else {
            return Err(TxError::Validation(
                InvalidTransaction::OverflowPaymentInTransaction,
            ));
        };

        value
    } else {
        U256::ZERO
    };
    let fee_to_prepay = gas_fee_amount
        .checked_add(fee_for_blob_gas)
        .ok_or(internal_error!("gfa+ffbg"))?;
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L514-516)
```rust
        let token_to_pay_operator = U256::from(context.gas_used)
            .checked_mul(gas_price_for_operator)
            .ok_or(internal_error!("gu*gpfo"))?;
```
