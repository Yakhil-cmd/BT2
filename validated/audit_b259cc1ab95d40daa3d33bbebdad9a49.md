### Title
`validate_l2_tx_intrinsic_native_resources` Missing Intrinsic EVM Gas Check Causes False-Positive Pre-Validation - (File: `api/src/helpers.rs`)

---

### Summary

The public API function `validate_l2_tx_intrinsic_native_resources` in `api/src/helpers.rs` is documented as mirroring the bootloader's intrinsic resource checks for L2 transactions. However, it omits the intrinsic EVM gas check (`gas_limit >= intrinsic_gas`) that the bootloader always enforces. The bootloader computes `calldata_tokens` from the actual calldata bytes and uses them to derive `intrinsic_gas`; the API function never performs this check. As a result, the function can return `Ok(())` for transactions that the bootloader will reject with `OutOfGasDuringValidation`, producing false-positive pre-validation results.

---

### Finding Description

The function `validate_l2_tx_intrinsic_native_resources` is described as:

> "This mirrors the intrinsic-resource checks performed by the bootloader during L2 tx validation without requiring the full system infrastructure." [1](#0-0) 

It accepts `calldata_length: u64` and checks only two things:

1. `native_limit >= intrinsic_pubdata_overhead` (pubdata native cost)
2. `native_limit >= intrinsic_computational_native` (computational native cost) [2](#0-1) 

The actual bootloader validation in `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs` performs an additional, mandatory third check: it computes `calldata_tokens` from the actual calldata bytes, derives `intrinsic_gas` from them, and then calls `create_resources_for_tx` which enforces `gas_limit >= intrinsic_gas`: [3](#0-2) 

Inside `create_resources_for_tx`, the intrinsic gas check is:

```rust
let gas_limit_for_tx = match gas_limit.checked_sub(intrinsic_gas) {
    Some(val) => val,
    None => P::handle_arithmetic_error(system, P::intrinsic_gas_overflow_error(...))?,
};
``` [4](#0-3) 

The `intrinsic_gas` is computed by `calculate_tx_intrinsic_gas`, which depends on `calldata_tokens` (a weighted count of zero vs. non-zero calldata bytes): [5](#0-4) 

`calldata_tokens` is computed by `compute_calldata_tokens`, which requires the actual calldata bytes — not just the length: [6](#0-5) 

The API function `validate_l2_tx_intrinsic_native_resources` receives only `calldata_length: u64` and never computes `calldata_tokens` or checks `gas_limit >= intrinsic_gas`. This is the same class of bug as the original report: the estimation/validation function uses incomplete data compared to what the actual execution path requires.

---

### Impact Explanation

Any external caller (sequencer, RPC node, SDK, wallet) that uses `validate_l2_tx_intrinsic_native_resources` to pre-screen L2 transactions before submission will receive a false `Ok(())` for transactions where `gas_limit < intrinsic_gas`. Those transactions will be submitted to the bootloader and rejected with `OutOfGasDuringValidation`. The user's transaction fails and the gas fee is wasted. This is a resource accounting mismatch between the API estimation layer and the actual bootloader execution path.

---

### Likelihood Explanation

The likelihood is high. Any transaction with non-trivial calldata (especially calldata with many non-zero bytes, which have a higher token weight) will have a larger `intrinsic_gas`. A caller that sets `gas_limit` just above the native-resource threshold (which `validate_l2_tx_intrinsic_native_resources` does check) but below the EVM intrinsic gas threshold (which it does not check) will receive a false positive. This is a common scenario for transactions with moderate-to-large calldata payloads.

---

### Recommendation

The function `validate_l2_tx_intrinsic_native_resources` should also compute `calldata_tokens` from the actual calldata bytes (or accept them as a parameter) and verify `gas_limit >= intrinsic_gas` using `calculate_tx_intrinsic_gas`, mirroring the full set of checks performed by `create_resources_for_tx` in the bootloader. Alternatively, the function's documentation should be updated to clearly state that it does **not** check EVM intrinsic gas sufficiency, so callers know to perform that check separately.

---

### Proof of Concept

1. Construct a transaction with `calldata` consisting entirely of non-zero bytes (e.g., 200 bytes of `0xFF`). Non-zero bytes have a higher token weight, so `calldata_tokens` will be large and `intrinsic_gas` will be significantly above `TX_INTRINSIC_GAS`.
2. Set `gas_limit` to a value that satisfies the native resource check (passes `validate_l2_tx_intrinsic_native_resources`) but is below `intrinsic_gas` (e.g., `TX_INTRINSIC_GAS + 1`).
3. Call `validate_l2_tx_intrinsic_native_resources` with this `gas_limit` and `calldata_length = 200`. The function returns `Ok(())`.
4. Submit the transaction to the bootloader. The bootloader calls `create_resources_for_tx` → `gas_limit.checked_sub(intrinsic_gas)` returns `None` → transaction is rejected with `OutOfGasDuringValidation`.

The discrepancy arises because `validate_l2_tx_intrinsic_native_resources` never calls `calculate_tx_intrinsic_gas` and never subtracts `intrinsic_gas` from `gas_limit`. [7](#0-6) [8](#0-7)

### Citations

**File:** api/src/helpers.rs (L381-461)
```rust
/// Validates that a transaction provides enough gas limit and gas price
/// to cover intrinsic native resources (computational native + pubdata).
///
/// This mirrors the intrinsic-resource checks performed by the bootloader
/// during L2 tx validation without requiring the full system infrastructure.
/// It also validates fee fields(base_fee, native_price, max_fee_per_gas, max_priority_fee_per_gas)
///
/// Please note, that it works only for Ethereum tx types (doesn't work for service txs)
#[allow(clippy::too_many_arguments)]
#[allow(clippy::result_unit_err)]
pub fn validate_l2_tx_intrinsic_native_resources(
    base_fee: U256,
    native_price: U256,
    pubdata_price: U256,
    gas_limit: u64,
    calldata_length: u64,
    access_list_accounts: u64,
    access_list_storage_keys: u64,
    authorization_list_num: u64,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
) -> Result<(), ()> {
    // Validate fee fields
    if max_priority_fee_per_gas > max_fee_per_gas {
        return Err(());
    }
    if base_fee > max_fee_per_gas {
        return Err(());
    }

    // Compute effective gas price
    let gas_price = if base_fee == 0 {
        // Following bootloader: if base fee is zero, then we ignore priority fee
        U256::ZERO
    } else {
        let priority_fee = min(max_priority_fee_per_gas, max_fee_per_gas - base_fee);
        base_fee + priority_fee
    };

    // native_per_gas = ceil(gas_price / native_price)
    if native_price.is_zero() {
        return Err(());
    }
    let native_per_gas = u256_try_to_u64(&gas_price.div_ceil(native_price)).ok_or(())?;

    // native_per_pubdata = pubdata_price / native_price
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price)).ok_or(())?;

    // following bootloader behavior
    let native_limit = if native_per_gas == 0 {
        u64::MAX - 1
    } else {
        native_per_gas.saturating_mul(gas_limit)
    };

    // Intrinsic pubdata
    let intrinsic_pubdata = calculate_l2_tx_intrinsic_pubdata(authorization_list_num, false);
    let intrinsic_pubdata_overhead = native_per_pubdata.saturating_mul(intrinsic_pubdata);

    let native_limit = native_limit
        .checked_sub(intrinsic_pubdata_overhead)
        .ok_or(())?;

    // Cap at MAX_NATIVE_COMPUTATIONAL (excess is withheld for pubdata only)
    let native_limit = native_limit.min(MAX_NATIVE_COMPUTATIONAL);

    // Intrinsic computational native
    let intrinsic_computational_native = calculate_l2_tx_intrinsic_computational_native_resources(
        calldata_length,
        access_list_accounts,
        access_list_storage_keys,
        authorization_list_num,
        false,
    );

    native_limit
        .checked_sub(intrinsic_computational_native)
        .ok_or(())?;

    Ok(())
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L174-202)
```rust
    let intrinsic_gas = calculate_tx_intrinsic_gas(
        calldata.len() as u64,
        calldata_tokens,
        is_deployment,
        access_list_accounts,
        access_list_storage_keys,
        authorization_list_num,
    );
    let intrinsic_computational_native = calculate_l2_tx_intrinsic_computational_native_resources(
        calldata.len() as u64,
        access_list_accounts,
        access_list_storage_keys,
        authorization_list_num,
        transaction.is_service(),
    );
    let intrinsic_pubdata =
        calculate_l2_tx_intrinsic_pubdata(authorization_list_num, transaction.is_service());

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L520-542)
```rust
pub(crate) fn compute_calldata_tokens<S: SystemTypes>(
    system: &mut System<S>,
    calldata: &[u8],
) -> (u64, u64) {
    let zero_bytes = calldata.iter().filter(|byte| **byte == 0).count() as u64;
    let non_zero_bytes = (calldata.len() as u64) - zero_bytes;
    let zero_bytes_factor = zero_bytes.saturating_mul(CALLDATA_ZERO_BYTE_TOKEN_FACTOR);
    let non_zero_bytes_factor = non_zero_bytes.saturating_mul(CALLDATA_NON_ZERO_BYTE_TOKEN_FACTOR);
    let num_tokens = zero_bytes_factor.saturating_add(non_zero_bytes_factor);

    #[cfg(feature = "eip_7623")]
    {
        let floor_tokens_gas_cost = num_tokens.saturating_mul(TOTAL_COST_FLOOR_PER_TOKEN);
        let intrinsic_gas = TX_INTRINSIC_GAS.saturating_add(floor_tokens_gas_cost);

        (num_tokens, intrinsic_gas)
    }

    #[cfg(not(feature = "eip_7623"))]
    {
        (num_tokens, 0)
    }
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L263-300)
```rust
pub fn calculate_tx_intrinsic_gas(
    calldata_len: u64,
    calldata_tokens: u64,
    is_deployment: bool,
    access_list_accounts: u64,
    access_list_storage_keys: u64,
    authorization_list_num: u64,
) -> u64 {
    let mut intrinsic_gas = TX_INTRINSIC_GAS;

    if is_deployment {
        intrinsic_gas = intrinsic_gas.saturating_add(DEPLOYMENT_TX_EXTRA_INTRINSIC_GAS);
        let initcode_gas_cost =
            evm_interpreter::gas_constants::INITCODE_WORD_COST * calldata_len.div_ceil(32);
        intrinsic_gas = intrinsic_gas.saturating_add(initcode_gas_cost);
    }
    intrinsic_gas =
        intrinsic_gas.saturating_add(calldata_tokens.saturating_mul(CALLDATA_TOKEN_GAS_COST));

    // EIP-2930 access list: per-address + per-storage-key.
    intrinsic_gas = intrinsic_gas.saturating_add(
        access_list_accounts.saturating_mul(evm_interpreter::gas_constants::ACCESS_LIST_ADDRESS),
    );
    intrinsic_gas = intrinsic_gas.saturating_add(
        access_list_storage_keys
            .saturating_mul(evm_interpreter::gas_constants::ACCESS_LIST_STORAGE_KEY),
    );

    // EIP-7702 authorization list: per-authorization. We precharge the
    // empty-account cost; when the authority turns out to be non-empty the
    // delta (NEWACCOUNT - PER_AUTH_BASE_COST) is added back as a gas refund
    // inside `validate_and_apply_delegation`.
    intrinsic_gas = intrinsic_gas.saturating_add(
        authorization_list_num.saturating_mul(evm_interpreter::gas_constants::NEWACCOUNT),
    );

    intrinsic_gas
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L396-413)
```rust
    // Check if intrinsic gas exceeds gas limit
    let gas_limit_for_tx = match gas_limit.checked_sub(intrinsic_gas) {
        Some(val) => val,
        None => P::handle_arithmetic_error(
            system,
            P::intrinsic_gas_overflow_error(intrinsic_gas, gas_limit),
        )?,
    };

    let ergs = gas_limit_for_tx.saturating_mul(ERGS_PER_GAS); // we checked at the very start that gas_limit * ERGS_PER_GAS doesn't overflow
    let main_resources = S::Resources::from_ergs_and_native(Ergs(ergs), native_limit);

    Ok(ResourcesForTx {
        main_resources,
        withheld,
        intrinsic_computational_native_charged: intrinsic_computational_native,
    })
}
```
