### Title
EVM Gas Refund Silently Discarded When `minimal_gas_used` Floor Overrides Post-Refund `gas_used` — (`basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs`)

---

### Summary

In `compute_gas_refund`, the EVM SSTORE gas refund is subtracted from `gas_used` and then a `minimal_gas_used` floor is applied via `core::cmp::max`. When the floor exceeds the post-refund value, the refund is silently discarded and the user is charged more gas than they are entitled to under EIP-3529. This is a direct, user-facing financial loss reachable by any unprivileged transaction sender.

---

### Finding Description

`compute_gas_refund` in `basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs` executes the following sequence:

```rust
// Step 1: subtract EVM refund from gas_used
gas_used -= evm_refund;

// Step 2: clamp to minimum floor — OVERRIDES the refund if floor > post-refund value
let mut gas_used = core::cmp::max(gas_used, minimal_gas_used);
``` [1](#0-0) 

For Ethereum-mode transactions, `minimal_gas_used` is set to `TX_INTRINSIC_GAS` (21 000 gas) in `validate_and_compute_fee_for_transaction`: [2](#0-1) 

This value flows into `before_refund` as `context.minimal_gas_to_charge` and is passed directly to `compute_gas_refund`: [3](#0-2) 

In standard Ethereum (EIP-3529), the refund is applied to total gas used and the result **can** fall below the intrinsic cost — there is no post-refund floor. ZKsync OS introduces a floor that is applied **after** the refund, which can silently cancel part or all of the user's entitled refund.

The EVM refund counter itself is correctly scoped per-transaction (reset in `begin_new_tx`) and correctly rolled back on frame revert: [4](#0-3) 

The accounting error is purely in the ordering of the floor vs. the refund subtraction.

---

### Impact Explanation

A user who sends an Ethereum-mode transaction that:
- uses gas close to the 21 000 intrinsic floor, **and**
- performs SSTORE operations that generate an EVM refund (e.g., resetting a slot from non-zero to zero)

will receive fewer tokens back than EIP-3529 entitles them to. The lost amount equals `min(evm_refund, minimal_gas_used − (gas_used − evm_refund))` gas units multiplied by the effective gas price. This is a direct, irreversible loss of user funds with no compensating gain to any party.

---

### Likelihood Explanation

The condition is triggered whenever `gas_used − evm_refund < minimal_gas_used`. Because `evm_refund ≤ gas_used / 5`, this requires `gas_used < minimal_gas_used × 5/4 = 26 250`. Any transaction that:

1. Executes a warm SSTORE from a non-zero value to zero (costs 100 gas, generates 4 800 gas refund), and
2. Has total gas usage between 21 000 and 26 250

satisfies the condition. A concrete minimal example: a contract call that uses 21 100 gas total (21 000 intrinsic + 100 for the SSTORE) produces `evm_refund = min(4800, 21100/5) = 4220`, leaving `gas_used − evm_refund = 16 880 < 21 000`. The floor clamps to 21 000, and the user loses 4 120 gas units of refund. This scenario is reachable by any unprivileged EOA.

---

### Recommendation

Apply the `minimal_gas_used` floor **before** subtracting the EVM refund, so the refund is always honoured on top of the minimum:

```

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L38-56)
```rust
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L137-163)
```rust
    let (calldata_tokens, minimal_gas_used) = {
        let zero_bytes = calldata.iter().filter(|byte| **byte == 0).count() as u64;
        let non_zero_bytes = (calldata.len() as u64) - zero_bytes;
        let zero_bytes_factor = zero_bytes.saturating_mul(CALLDATA_ZERO_BYTE_TOKEN_FACTOR);
        let non_zero_bytes_factor =
            non_zero_bytes.saturating_mul(CALLDATA_NON_ZERO_BYTE_TOKEN_FACTOR);
        let num_tokens = zero_bytes_factor.saturating_add(non_zero_bytes_factor);

        #[cfg(feature = "eip_7623")]
        {
            let floor_tokens_gas_cost = num_tokens.saturating_mul(TOTAL_COST_FLOOR_PER_TOKEN);
            let intrinsic_gas = TX_INTRINSIC_GAS.saturating_add(floor_tokens_gas_cost);

            require!(
                intrinsic_gas <= tx_gas_limit,
                InvalidTransaction::EIP7623IntrinsicGasIsTooLow,
                system
            )?;

            (num_tokens, intrinsic_gas)
        }

        #[cfg(not(feature = "eip_7623"))]
        {
            (num_tokens, TX_INTRINSIC_GAS)
        }
    };
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L474-488)
```rust
        let min_gas_used = context.minimal_gas_to_charge;
        // Compute gas used following the same logic as in normal execution

        let refund_info = compute_gas_refund(
            system,
            S::Resources::empty(),
            transaction.gas_limit(),
            min_gas_used,
            0u64,
            &mut context.resources.main_resources,
        )?;
        context.gas_used = refund_info.gas_used;

        Ok(())
    }
```

**File:** basic_system/src/system_implementation/caches/generic_pubdata_aware_plain_storage.rs (L102-106)
```rust
    pub fn begin_new_tx(&mut self) {
        self.cache.commit();
        self.evm_refunds_counter =
            NonEmptyHistoryCounter::new_with_initial(self.alloc.clone(), R::empty());
    }
```
