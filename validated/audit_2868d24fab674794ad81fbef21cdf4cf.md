[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L20-97)
```rust
pub(crate) fn compute_gas_refund<S: EthereumLikeTypes>(
    system: &mut System<S>,
    to_charge_for_pubdata: S::Resources,
    gas_limit: u64,
    minimal_gas_used: u64,
    native_per_gas: u64,
    resources: &mut S::Resources,
) -> Result<RefundInfo, InternalError> {
    // Already checked
    resources.charge_unchecked(&to_charge_for_pubdata);

    let mut gas_used = gas_limit
        .checked_sub(resources.ergs().0.div_floor(ERGS_PER_GAS))
        .ok_or(internal_error!("gas remaining > gas limit"))?;
    resources.exhaust_ergs();

    system_log!(system, "Gas used before refund calculations: {gas_used}\n");

    // Following EIP-3529, refunds are capped to 1/5 of the gas used
    let evm_refund = {
        let full_refund_ergs = system.io.get_refund_counter().ergs();
        let full_refund_gas = full_refund_ergs.0.div_floor(ERGS_PER_GAS);
        let max_refund = gas_used / 5;
        core::cmp::min(full_refund_gas, max_refund)
    };

    system_log!(system, "Gas refund from refund counters = {evm_refund}\n");

    gas_used -= evm_refund;

    system_log!(
        system,
        "Minimal gas used from validation = {minimal_gas_used}\n"
    );

    #[allow(unused_mut)]
    let mut gas_used = core::cmp::max(gas_used, minimal_gas_used);

    // Note: for zero gas price, we use "unlimited native"
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
    }

    let total_gas_refund = gas_limit - gas_used;
    system_log!(system, "Refund after accounting for unused gas, refund counters and native cost: {total_gas_refund}\n");
    require_internal!(
        total_gas_refund <= gas_limit,
        "Gas refund greater than gas limit",
        system
    )?;
    let refund_info = RefundInfo {
        gas_used,
        evm_refund,
        native_used,
    };
    system_log!(system, "Final gas used: {gas_used}\n");
    Ok(refund_info)
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L427-434)
```rust
        let refund_info = compute_gas_refund(
            system,
            to_charge_for_pubdata,
            transaction.gas_limit(),
            min_gas_used,
            context.native_per_gas,
            &mut context.resources.main_resources,
        )?;
```
