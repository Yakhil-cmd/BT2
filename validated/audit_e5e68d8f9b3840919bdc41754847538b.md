### Title
Asymmetric `delta_gas` Adjustment in `compute_gas_refund` Causes Systematic User Overcharging — (`basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

`compute_gas_refund` adjusts `gas_used` upward when native resource consumption exceeds EVM gas consumption (`delta_gas > 0`), but never adjusts it downward when native consumption is lower (`delta_gas < 0`). This mirrors the original report's root cause exactly: a resource-tracking variable is updated in one direction but not the other, causing a derived financial calculation to be systematically wrong. The result is that users are overcharged for gas whenever their transaction's native resource consumption is lower than its EVM gas consumption, with the surplus flowing to the operator.

---

### Finding Description

In `compute_gas_refund`, the double-resource accounting reconciliation step computes:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};

if delta_gas > 0 {
    // native cost > EVM gas cost → charge more gas
    gas_used += delta_gas as u64;
}
// TODO: return delta_gas to gas_used?
``` [1](#0-0) 

The `delta_gas` value is `(native_used / native_per_gas) - gas_used`:
- **Positive**: native resource cost (in gas-equivalent) exceeds EVM gas used → `gas_used` is increased so the user pays for the extra proving cost.
- **Negative**: native resource cost is *less* than EVM gas used → `gas_used` is **not** decreased. The user is overcharged by `|delta_gas|` gas units.

The TODO comment on line 80 is an explicit developer acknowledgment that the negative branch is unimplemented. The official documentation at `docs/double_resource_accounting.md` only describes the positive case:

> "If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs." [2](#0-1) 

The inflated `gas_used` then directly reduces the token refund returned to the sender and inflates the token payment sent to the coinbase:

```rust
// Refund = (gas_limit - gas_used) * gas_price  ← smaller than correct
let token_to_refund = context.gas_price * U256::from(context.tx_gas_limit - context.gas_used);
// Operator payment = gas_used * gas_price  ← larger than correct
let token_to_pay_operator = U256::from(context.gas_used).checked_mul(gas_price_for_operator)?;
``` [3](#0-2) 

The same `compute_gas_refund` function is called for both ZK (L2) transactions and Ethereum-type transactions, so both transaction flows are affected. [4](#0-3) 

---

### Impact Explanation

Every transaction where `native_used / native_per_gas < gas_used` results in the user being overcharged by `|delta_gas| * gas_price` tokens. The operator (coinbase) receives this surplus. The magnitude scales with:
- The gap between EVM gas consumption and native resource consumption.
- The transaction's gas price.

For L2 transactions, the overcharge comes directly out of the sender's pre-paid fee balance. For L1→L2 transactions, the overcharge reduces the refund minted back to the refund recipient from the treasury. [5](#0-4) 

---

### Likelihood Explanation

`delta_gas < 0` occurs whenever a transaction's EVM gas consumption exceeds its native resource consumption in gas-equivalent terms. This is the **expected common case** — the documentation explicitly states "We expect the base fee to be enough to cover most transactions without the need of additional gas," meaning `delta_gas > 0` is the *exceptional* case. Transactions heavy in warm SLOAD/SSTORE operations (cheap in native proving cycles but expensive in EVM gas) reliably produce a negative `delta_gas`. Any unprivileged transaction sender triggers this path simply by submitting a normal transaction.

---

### Recommendation

Apply the `delta_gas` adjustment symmetrically. When `delta_gas < 0`, decrease `gas_used` by `|delta_gas|`, subject to the `minimal_gas_used` floor:

```rust
if delta_gas > 0 {
    gas_used += delta_gas as u64;
} else if delta_gas < 0 {
    let reduction = (-delta_gas) as u64;
    gas_used = gas_used.saturating_sub(reduction).max(minimal_gas_used);
}
``` [6](#0-5) 

---

### Proof of Concept

Consider a ZK (L2) transaction with:
- `gas_limit = 100_000`
- `gas_price = 1_000` (wei)
- `native_per_gas = 1` (i.e., `gas_price / native_price = 1`)
- EVM execution consumes `80_000` gas → `gas_used = 80_000`
- Native execution consumes `50_000` native units → `native_used = 50_000`

**Correct accounting:**
- `delta_gas = (50_000 / 1) - 80_000 = -30_000`
- Correct `gas_used = 80_000 - 30_000 = 50_000`
- Correct refund = `(100_000 - 50_000) * 1_000 = 50_000_000` wei

**Actual accounting (bug):**
- `delta_gas = -30_000` → not applied
- Actual `gas_used = 80_000`
- Actual refund = `(100_000 - 80_000) * 1_000 = 20_000_000` wei

The user is overcharged by `30_000 * 1_000 = 30_000_000` wei, which is credited to the operator instead. [7](#0-6)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L55-83)
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
```

**File:** docs/double_resource_accounting.md (L47-51)
```markdown
Then we compute the difference between the implicit gas used derived from native resource consumption and the gas used by EEs from the ergs used. We call this value `deltaGas`.
  `deltaGas := (nativeUsed / nativePerGas) - gasUsed`

If `deltaGas > 0`, we add it to `gasUsed` and charge it from ergs. This ensures that gas estimation will include additional gas to cover for native resources using just base fee. We expect the base fee to be enough to cover most transactions without the need of additional gas.

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

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L477-485)
```rust
        let refund_info = compute_gas_refund(
            system,
            S::Resources::empty(),
            transaction.gas_limit(),
            min_gas_used,
            0u64,
            &mut context.resources.main_resources,
        )?;
        context.gas_used = refund_info.gas_used;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L277-334)
```rust
    let pay_to_operator = U256::from(gas_used)
        .checked_mul(U256::from(gas_price))
        .ok_or(internal_error!("gu*gp"))?;
    // Use FORMAL_INFINITE for post-execution operations (coinbase transfer,
    // asset tracker notifications, refund transfer, log emission).
    // These cannot fail due to resource exhaustion. Their native cost is
    // accounted for as intrinsic and is not included in
    // computational_native_used (native_used only reflects native for
    // pubdata + native used for charged computation).
    let mut inf_resources = S::Resources::FORMAL_INFINITE;

    let coinbase = system.get_coinbase();
    // Mint operator fee portion of the deposit to coinbase.
    mint_base_token::<S, Config>(
        system,
        system_functions,
        memories.reborrow(),
        &pay_to_operator,
        &coinbase,
        l1_chain_id,
        &mut inf_resources,
        tracer,
        validator,
    )
    .map_err(|e| match e.root_cause() {
        RootCause::Runtime(RuntimeError::OutOfErgs(_)) => {
            internal_error!("Out of ergs on infinite ergs").into()
        }
        RootCause::Runtime(RuntimeError::FatalRuntimeError(_)) => {
            internal_error!("Out of native on infinite").into()
        }
        _ => e,
    })?;

    // Refund
    let to_refund_recipient = if !is_success {
        // Upgrade transactions must always succeed
        if !is_priority_op {
            return Err(internal_error!("Upgrade transaction must succeed").into());
        }
        // If the transaction reverts, then the minting of the deposit
        // reverted too. Thus, we need to refund the entire deposit minus
        // the fee (`pay_to_operator`).
        total_deposited
            .checked_sub(pay_to_operator)
            .ok_or(internal_error!("td-pto"))
    } else {
        // If the transaction succeeds, then it is assumed that the
        // mint to `from` address was transferred correctly too.
        // In this case, we just refund the unused gas that the
        // transaction paid for initially.
        let prepaid_fee = gas_price
            .checked_mul(U256::from(transaction.gas_limit.read()))
            .ok_or(internal_error!("gp*gl"))?;
        prepaid_fee
            .checked_sub(pay_to_operator)
            .ok_or(internal_error!("pf-pto"))
    }?;
```
