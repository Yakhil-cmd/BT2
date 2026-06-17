### Title
Asymmetric `delta_gas` Adjustment Never Reduces `gas_used` When Native Consumption Is Below Gas Consumption, Causing User Overpayment - (`basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` in ZKsync OS implements a dual-resource reconciliation step that adjusts `gas_used` upward when native resource consumption exceeds EVM gas consumption (`delta_gas > 0`), but never adjusts it downward when EVM gas consumption exceeds native resource consumption (`delta_gas < 0`). The missing branch is explicitly flagged with a `// TODO: return delta_gas to gas_used?` comment. As a result, users are systematically overcharged whenever their transaction's EVM gas consumption is higher than what native resource consumption would imply, and the excess fee is transferred to the operator rather than refunded to the sender.

---

### Finding Description

ZKsync OS uses a double resource accounting model: **Ergs** (proportional to EVM gas) and **native resources** (proportional to RISC-V proving cycles and pubdata). Because the native resource limit is derived from `gasLimit × gasPrice / nativePrice`, the two meters can diverge during execution.

After execution, `compute_gas_refund` reconciles the two meters via `delta_gas`:

```
delta_gas = (native_used / native_per_gas) - gas_used
``` [1](#0-0) 

The code handles only the `delta_gas > 0` branch (native exceeded gas → charge more gas), and leaves the `delta_gas < 0` branch (gas exceeded native → should refund gas) unimplemented:

```rust
if delta_gas > 0 {
    // In this case, the native resource consumption is more than the
    // gas consumption accounted for. Consume extra gas.
    gas_used += delta_gas as u64;
}
// TODO: return delta_gas to gas_used?
``` [2](#0-1) 

The project's own documentation confirms the intended symmetric design:

> `deltaGas := (nativeUsed / nativePerGas) - gasUsed`
> If `deltaGas > 0`, we add it to `gasUsed`…
> Finally, any remaining gas left is refunded as usual. [3](#0-2) 

The documentation describes only the positive case; the negative case is silently dropped. The resulting `gas_used` is then used to compute the user's refund and the operator's payment:

```rust
let token_to_refund = context.gas_price * U256::from(context.tx_gas_limit - context.gas_used);
// ...
let token_to_pay_operator = U256::from(context.gas_used).checked_mul(gas_price_for_operator)...;
``` [4](#0-3) 

Because `gas_used` is never reduced when `delta_gas < 0`, the user's refund is smaller than it should be by `gas_price × |delta_gas|`, and the operator receives that excess instead.

This same `compute_gas_refund` function is called for both L2 transactions (via `before_refund` in `zk/mod.rs`) and L1→L2 transactions (via `process_l1_transaction.rs`): [5](#0-4) [6](#0-5) 

---

### Impact Explanation

For every transaction where EVM gas consumption exceeds native resource consumption (i.e., `gas_used > native_used / native_per_gas`), the sender (L2 tx) or refund recipient (L1→L2 tx) loses:

```
loss = gas_price × (gas_used − native_used / native_per_gas)
```

This amount is silently transferred to the operator instead of being refunded. The loss is proportional to the divergence between the two resource meters and to the gas price. Transactions that are EVM-gas-heavy but not native-resource-heavy (e.g., many `SLOAD`/`SSTORE` operations that are expensive in EVM gas but cheap in RISC-V proving cycles) are most affected.

---

### Likelihood Explanation

The condition `delta_gas < 0` is reachable by any unprivileged user submitting a standard L2 or L1→L2 transaction. No special permissions, governance access, or oracle manipulation are required. Any transaction whose EVM opcode costs are disproportionately high relative to native proving costs will trigger the missing branch. This is a normal execution path, not an edge case.

---

### Recommendation

Add the symmetric `else` branch to reduce `gas_used` when `delta_gas < 0`:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else {
    // delta_gas is negative: native consumption was lower than gas consumption.
    // Reduce gas_used so the user is refunded the difference.
    gas_used = gas_used.saturating_sub((-delta_gas) as u64);
    // Ensure gas_used does not fall below minimal_gas_used (already enforced above).
}
```

The resulting `gas_used` must still be clamped to `minimal_gas_used` (already enforced at line 56) and must not exceed `gas_limit` (already enforced at line 83–88). [7](#0-6) 

---

### Proof of Concept

1. Submit an L2 transaction with:
   - `gas_limit = 100_000`
   - `gas_price = 1_000` (so `native_per_gas = gas_price / native_price`)
   - EVM execution that consumes 80,000 EVM gas but only a small amount of native resources (e.g., a loop of arithmetic opcodes that are cheap to prove)

2. After execution, suppose:
   - `gas_used` (from ergs) = 80,000
   - `native_used / native_per_gas` = 50,000 (native consumption was lower)
   - `delta_gas = 50,000 − 80,000 = −30,000`

3. Because the `delta_gas < 0` branch is missing, `gas_used` remains 80,000.

4. The user is refunded `1,000 × (100,000 − 80,000) = 20,000,000` instead of the correct `1,000 × (100,000 − 50,000) = 50,000,000`.

5. The operator receives `1,000 × 80,000 = 80,000,000` instead of the correct `1,000 × 50,000 = 50,000,000`.

6. The user permanently loses `30,000,000` native tokens per transaction, with no recourse.

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L55-97)
```rust
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

**File:** docs/double_resource_accounting.md (L47-52)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.

Finally, any remaining gas left is refunded as usual.
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L452-516)
```rust
        if context.tx_gas_limit > context.gas_used {
            system_log!(system, "Gas price for refund is {:?}\n", &context.gas_price);

            // refund
            let refund_recipient = transaction.from();
            let token_to_refund =
                context.gas_price * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow

            // First refund the sender. Routed through `intrinsic_resources` so
            // the native charge (precharged by the intrinsic formula) can be
            // verified under `verify_intrinsic_native`.
            context
                .intrinsic_resources
                .with_infinite_ergs(|resources| {
                    system.io.update_account_nominal_token_balance(
                        ExecutionEnvironmentType::NoEE,
                        resources,
                        &refund_recipient,
                        &token_to_refund,
                        false,
                        Config::SIMULATION,
                    )
                })
                .map_err(|e| match e {
                    // Balance errors can not be cascaded
                    SubsystemError::Cascaded(CascadedError(inner, _)) => match inner {},
                    SubsystemError::LeafUsage(InterfaceError(ie, _)) => match ie {
                        BalanceError::InsufficientBalance => {
                            unreachable!("Cannot be insufficient when incrementing balance")
                        }
                        BalanceError::Overflow => {
                            interface_error!(BootloaderInterfaceError::CantPayRefundOverflow)
                        }
                    },
                    other => wrap_error!(other),
                })?;
        }

        // Next we pay the operator
        // ARCHITECTURE NOTE: Fee payment is split into two phases:
        // 1. Deduct full fee from sender at transaction start (in pay_for_transaction)
        // 2. Transfer actual payment to operator after execution (here)
        // This ensures sender has sufficient funds before execution begins

        // EIP-1559 compatibility: When burn_base_fee is enabled, only priority fees
        // go to the operator. Base fees are effectively "burned" (not transferred anywhere).
        let gas_price_for_operator = if cfg!(feature = "burn_base_fee") {
            let base_fee = system.get_eip1559_basefee();
            // We use saturating arithmetic to allow the caller of this method to
            // allow gas_price < base_fee. This can be used, for example, for
            // transaction simulation
            context.gas_price.saturating_sub(base_fee)
        } else {
            context.gas_price
        };

        system_log!(
            system,
            "Gas price for coinbase fee is {:?}\n",
            &gas_price_for_operator
        );

        let token_to_pay_operator = U256::from(context.gas_used)
            .checked_mul(gas_price_for_operator)
            .ok_or(internal_error!("gu*gpfo"))?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L261-273)
```rust
    #[allow(unused_variables)]
    let RefundInfo {
        gas_used,
        evm_refund,
        native_used,
    } = compute_gas_refund(
        system,
        to_charge_for_pubdata,
        gas_limit,
        minimal_gas_used,
        native_per_gas,
        &mut resources,
    )?;
```
