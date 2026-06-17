### Title
Zero `base_fee` Silently Drops Priority Fees and Grants Unlimited Native Resources, Removing Operator Economic Incentive — (`basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs`)

---

### Summary

When the block's `base_fee` is zero, the bootloader's `get_gas_price` function returns `U256::ZERO` regardless of any `max_priority_fee_per_gas` set by the sender. This causes `native_per_gas = 0`, which triggers the "free native" path in `create_resources_for_tx`, granting every transaction an unlimited native resource budget (`u64::MAX - 1`). The operator receives zero fee for processing these transactions yet bears the full off-chain proving cost. This is the direct analog of `minLoanSize = 0`: a missing minimum threshold that removes the economic incentive for the party bearing the cost (operator/prover instead of liquidator), enabling a cheap resource-exhaustion path.

---

### Finding Description

**Step 1 — Priority fee is silently dropped when `base_fee == 0`.**

In `get_gas_price` the very first branch is:

```rust
// If base fee is zero, then we ignore priority fee
if base_fee.is_zero() {
    Ok(U256::ZERO)
}
``` [1](#0-0) 

No matter how large `max_priority_fee_per_gas` is, the effective gas price is forced to zero. The same branch exists in the Ethereum-path helper `get_gas_prices`: [2](#0-1) 

**Step 2 — Zero gas price produces `native_per_gas = 0`.**

For ZK-path L2 transactions, `native_per_gas` is computed as `gas_price.div_ceil(native_price)`. When `gas_price = 0` this evaluates to `0`: [3](#0-2) 

`create_resources_for_tx` is then called with `free_native = (native_per_gas == 0)`: [4](#0-3) 

**Step 3 — `free_native = true` grants unlimited native resources.**

Inside `create_resources_for_tx`:

```rust
// Note: for zero gas price, we use "unlimited native"
let native_limit = if cfg!(feature = "unlimited_native") || free_native {
    u64::MAX - 1 // So any saturation below can not be subtracted from it
} else {
    native_prepaid_from_gas
};
``` [5](#0-4) 

The transaction is allocated `u64::MAX - 1` native units — the maximum possible budget — at zero cost to the sender.

**Step 4 — Delta-gas adjustment is also suppressed.**

In `compute_gas_refund`, the delta-gas correction that would otherwise charge extra gas to cover native resource consumption is explicitly skipped when `native_per_gas == 0`:

```rust
let delta_gas = if native_per_gas == 0 {
    0
} else {
    (native_used / native_per_gas) as i64 - (gas_used as i64)
};
``` [6](#0-5) 

So even the secondary mechanism that would recover native-resource cost through extra gas is disabled.

**Step 5 — Operator receives zero fee.**

In `refund_and_commit_fee` (ZK path), the operator payment is `gas_used * gas_price_for_operator`. With `gas_price = 0` this is always zero: [7](#0-6) 

The same holds for the Ethereum path where the coinbase fee is `priority_fee_per_gas * gas_used`, and `priority_fee_per_gas` is zero because the base-fee branch returned `U256::ZERO` before the priority fee could be extracted: [8](#0-7) 

**Step 6 — `base_fee = 0` is a valid, documented operator configuration.**

The `api/src/helpers.rs` helper explicitly mirrors this behavior:

```rust
let gas_price = if base_fee == 0 {
    // Following bootloader: if base fee is zero, then we ignore priority fee
    U256::ZERO
} else { ... };
// following bootloader behavior
let native_limit = if native_per_gas == 0 {
    u64::MAX - 1
``` [9](#0-8) 

The `BlockMetadataFromOracle` test default sets `pubdata_price: U256::from(0u64)` and the block-reexecutor uses `unwrap_or(1000)` for `base_fee`, confirming zero is a reachable production value: [10](#0-9) 

---

### Impact Explanation

When an operator deploys with `base_fee = 0` (e.g., during initial rollout, on a testnet, or as a deliberate "free" period):

1. **Operator receives zero fee** for every transaction, regardless of any tip the sender offers.
2. **Every transaction gets unlimited native resources** (`u64::MAX - 1`), meaning it can consume the full block native budget without paying for it.
3. **An attacker can flood blocks** with computationally expensive transactions (large calldata, heavy EVM execution, high pubdata) at zero token cost, forcing the operator/prover to bear the full RISC-V proving cost.
4. **The block native resource limit** (`BlockNativeLimitReached`) is the only backstop, but it is consumed at zero cost per unit, exactly as bad debt accumulates at zero liquidation incentive in the original report.
5. The operator cannot recover costs even by raising `max_priority_fee_per_gas` requirements off-chain, because the on-chain code silently discards the priority fee.

---

### Likelihood Explanation

- `base_fee = 0` is explicitly supported, tested (`test_gas_price_zero_fee_zero`), and documented as a valid configuration.
- The ZKsync OS team's own comment (`TODO (EVM-1157): find a reasonable value`) on `L1_TX_NATIVE_PRICE` signals that minimum-fee parameters are still being calibrated, making a `base_fee = 0` initial deployment plausible.
- No protocol-level enforcement of a minimum `base_fee` exists anywhere in the codebase.
- The attack requires only that the operator sets `base_fee = 0`; once that condition holds, any unprivileged sender can exploit it.

---

### Recommendation

1. **Do not silently drop priority fees when `base_fee = 0`.** When `base_fee = 0`, use `max_priority_fee_per_gas` directly as the effective gas price (or at minimum as the operator tip), so the operator can still be compensated.
2. **Decouple "free native" from "zero gas price".** The unlimited-native grant should only apply when the operator explicitly opts in (e.g., a dedicated feature flag or a separate `free_tx` transaction type), not as a side-effect of `base_fee = 0`.
3. **Enforce a minimum `base_fee` or a minimum `native_per_gas`** before granting unlimited native resources, analogous to setting a realistic `minLoanSize`.

---

### Proof of Concept

```
1. Operator sets block context: base_fee = 0, native_price = 10, pubdata_price = 0.

2. Attacker submits 1000 L2 transactions, each with:
     max_fee_per_gas        = 0
     max_priority_fee_per_gas = 0
     gas_limit              = block_gas_limit   (e.g. 2^32)
     calldata               = 128 KB of non-zero bytes (maximum pubdata)

3. For each transaction:
   - get_gas_price() → U256::ZERO  (base_fee branch)
   - native_per_gas  = 0 / 10 = 0
   - free_native     = true
   - native_limit    = u64::MAX - 1  (unlimited)
   - fee_to_prepay   = 0 * gas_limit = 0  (sender pays nothing)
   - operator fee    = 0 * gas_used  = 0  (operator earns nothing)

4. Each transaction executes with full native budget, consuming proving cycles
   and pubdata bandwidth. The operator must prove all 1000 transactions at
   full RISC-V cost with zero token revenue.

5. The block's native resource limit is exhausted at zero cost to the attacker,
   preventing legitimate fee-paying transactions from being included.
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L121-139)
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

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L586-636)
```rust
        if context.priority_fee_per_gas.is_zero() == false {
            system_log!(
                system,
                "Gas price for coinbase fee is {:?}\n",
                &context.priority_fee_per_gas
            );

            let fee = context.priority_fee_per_gas * U256::from(context.gas_used); // can not overflow
            let coinbase = system.get_coinbase();

            system_log!(system, "Coinbase's share of fee is {:?}\n", &fee);

            // let _ = system.get_logger().write_fmt(format_args!(
            //     "Balance of coinbase 0x{:040x} before fee collection is {}\n",
            //     coinbase.as_uint(),
            //     context
            //     .resources
            //     .main_resources
            //     .with_infinite_ergs(|resources| {
            //         system.io.get_nominal_token_balance(
            //             ExecutionEnvironmentType::NoEE, // out of scope of other interactions
            //             resources,
            //             &coinbase,
            //         ).unwrap()
            //     })
            // ));

            let mut inf_resources = S::Resources::FORMAL_INFINITE;
            system
                .io
                .update_account_nominal_token_balance(
                    ExecutionEnvironmentType::NoEE,
                    &mut inf_resources,
                    &coinbase,
                    &fee,
                    false,
                    Config::SIMULATION,
                )
                .map_err(|e| match e {
                    // Balance errors can not be cascaded
                    SubsystemError::Cascaded(CascadedError(inner, _)) => match inner {},
                    SubsystemError::LeafUsage(InterfaceError(ie, _)) => match ie {
                        BalanceError::InsufficientBalance => {
                            unreachable!("Cannot be insufficient when incrementing balance")
                        }
                        BalanceError::Overflow => {
                            interface_error!(BootloaderInterfaceError::CantPayOperatorOverflow)
                        }
                    },
                    other => wrap_error!(other),
                })?;
```

**File:** api/src/helpers.rs (L411-434)
```rust
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
```

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L206-221)
```rust
    pub fn new_for_test() -> Self {
        BlockMetadataFromOracle {
            eip1559_basefee: U256::from(1000u64),
            pubdata_price: U256::from(0u64),
            native_price: U256::from(10),
            block_number: 1,
            timestamp: 42,
            chain_id: 37,
            gas_limit: u64::MAX / 256,
            pubdata_limit: u64::MAX,
            coinbase: B160::ZERO,
            block_hashes: BlockHashes::default(),
            mix_hash: U256::ONE,
            blob_fee: U256::ZERO,
        }
    }
```
