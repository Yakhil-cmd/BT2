### Title
Unlimited Native Resource Allocation Without Proportional Payment in Ethereum STF - (File: `basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs`)

---

### Summary

The Ethereum STF transaction flow unconditionally grants every transaction a native resource limit of `u64::MAX`, regardless of the gas price or gas limit paid. This is the direct analog of the "unlimited approval" pattern: just as `token.approve(spender, type(uint256).max)` grants unbounded token transfer rights without a proportional limit, hardcoding `native_limit = u64::MAX` grants unbounded prover-cycle consumption rights without proportional payment. An unprivileged sender can submit a transaction with minimal fees but force the prover to perform near-maximum native work, breaking the economic model and potentially exhausting the block-level native budget cheaply.

---

### Finding Description

In `basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs`, the private `create_resources_for_tx` function constructs the initial resources for every Ethereum STF transaction:

```rust
let native_limit =
    <<S as zk_ee::system::SystemTypes>::Resources as Resources>::Native::from_computational(
        u64::MAX,
    );
let main_resources = S::Resources::from_ergs_and_native(Ergs(ergs), native_limit);
``` [1](#0-0) 

The native resource is ZKsync OS's model for prover complexity — "how many RISC-V cycles it takes to prove a given computation." The ZK STF (`gas_helpers.rs`) derives the native limit proportionally from the transaction's gas price and gas limit:

```
native_limit = (gas_price / native_price) * gas_limit
```

and then caps it at `MAX_NATIVE_COMPUTATIONAL` (= 2^35): [2](#0-1) [3](#0-2) 

The Ethereum STF path skips this derivation entirely. The `ResourcesForEthereumTx` struct has no `withheld` field and no `MAX_NATIVE_COMPUTATIONAL` cap: [4](#0-3) 

The ZK STF only uses `u64::MAX - 1` when `free_native` is true (zero gas price) or the `unlimited_native` feature flag is active — both intentional, bounded exceptions. The Ethereum STF applies this unconditionally to every transaction. [5](#0-4) 

---

### Impact Explanation

**Vulnerability class:** Resource accounting bug / valid-execution unprovability.

1. **Prover DoS without proportional payment:** A transaction paying the minimum 21,000 gas (intrinsic cost) receives `u64::MAX` native resources. The user pays only for ergs (EVM gas), not for native (prover cycles). Expensive EVM operations — precompile calls, large memory expansions, deep call stacks — consume native resources. An attacker can craft a transaction that exhausts the block's native budget while paying only the gas cost of those operations, not the native cost.

2. **Block-level native budget exhaustion:** The block enforces `BlockNativeLimitReached`. A single Ethereum STF transaction with `u64::MAX` native budget can consume the entire block's native allowance, preventing other transactions from being included, at the cost of only the EVM gas for the expensive operations.

3. **Economic model breakage:** The ZK STF's double-resource accounting model is designed so that `nativeUsed / nativePerGas` is reflected back into `gasUsed` (delta gas), ensuring users pay for prover work. The Ethereum STF bypasses this entirely — native consumption is never charged back to the sender. [6](#0-5) 

---

### Likelihood Explanation

**High likelihood.** The attack requires only:
1. Submitting a standard Ethereum transaction through the Ethereum STF.
2. Including EVM operations with high native cost (e.g., precompile calls, large MSTORE/MCOPY, complex arithmetic).
3. No privileged access, no leaked keys, no oracle manipulation.

The attacker controls the calldata and target contract entirely. The entry path is the standard transaction submission interface.

---

### Recommendation

Replace the hardcoded `u64::MAX` in `create_resources_for_tx` (Ethereum STF) with the same proportional derivation used by the ZK STF in `gas_helpers.rs`:

1. Accept `effective_gas_price` and `native_price` as parameters (already computed during validation).
2. Compute `native_per_gas = effective_gas_price / native_price`.
3. Compute `native_limit = native_per_gas * gas_limit_for_tx`.
4. Cap at `MAX_NATIVE_COMPUTATIONAL` and withhold the excess (as `ResourcesForTx` does).
5. Use `u64::MAX - 1` only when `native_per_gas == 0` (zero gas price), consistent with the ZK STF.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker submits an Ethereum STF transaction with `gas_limit = MAX_BLOCK_GAS_LIMIT` and `max_fee_per_gas = base_fee` (minimum valid fee).
2. `validate_and_compute_fee_for_transaction` calls `create_resources_for_tx`, which sets `native_limit = u64::MAX`.
3. The transaction's calldata targets a contract that calls expensive precompiles (e.g., `modexp`, `ecpairing`) or performs large memory operations in a loop.
4. Each precompile call charges native resources (e.g., `BIGINT_DELEGATION_COEFFICIENT = 4` per bigint op, `BLAKE_DELEGATION_COEFFICIENT = 16` per blake op).
5. The transaction consumes native resources far exceeding what `gas_price * gas_limit / native_price` would have permitted under the ZK STF model.
6. The block's `BlockNativeLimitReached` check fires, or the prover receives a block with native consumption that was not economically bounded.

**Contrast with ZK STF:** The same transaction submitted through the ZK STF would be bounded by `native_limit = (gas_price / native_price) * gas_limit ≤ MAX_NATIVE_COMPUTATIONAL`, and any excess native consumption would be reflected as `deltaGas` charged back to the sender. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L26-60)
```rust
fn create_resources_for_tx<S: EthereumLikeTypes>(
    gas_limit: u64,
    is_deployment: bool,
    calldata_len: u64,
    calldata_tokens: u64,
) -> Result<ResourcesForEthereumTx<S>, TxError> {
    let mut intrinsic_overhead = TX_INTRINSIC_GAS;
    if is_deployment {
        if calldata_len > MAX_INITCODE_SIZE as u64 {
            return Err(TxError::Validation(CreateInitCodeSizeLimit));
        }
        intrinsic_overhead = intrinsic_overhead.saturating_add(DEPLOYMENT_TX_EXTRA_INTRINSIC_GAS);
        let initcode_gas_cost =
            evm_interpreter::gas_constants::INITCODE_WORD_COST * calldata_len.div_ceil(32);
        intrinsic_overhead = intrinsic_overhead.saturating_add(initcode_gas_cost);
    }
    intrinsic_overhead =
        intrinsic_overhead.saturating_add(calldata_tokens.saturating_mul(CALLDATA_TOKEN_GAS_COST));

    if intrinsic_overhead > gas_limit {
        Err(TxError::Validation(
            InvalidTransaction::OutOfGasDuringValidation,
        ))
    } else {
        let gas_limit_for_tx = gas_limit - intrinsic_overhead;
        let ergs = gas_limit_for_tx.saturating_mul(ERGS_PER_GAS); // we checked at the very start that gas_limit * ERGS_PER_GAS doesn't overflow
        let native_limit =
            <<S as zk_ee::system::SystemTypes>::Resources as Resources>::Native::from_computational(
                u64::MAX,
            );
        let main_resources = S::Resources::from_ergs_and_native(Ergs(ergs), native_limit);

        Ok(ResourcesForEthereumTx { main_resources })
    }
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L324-413)
```rust
pub fn create_resources_for_tx<S: EthereumLikeTypes, P: ResourcesCreationErrorPolicy<S>>(
    system: &mut System<S>,
    gas_limit: u64,
    free_native: bool,
    native_prepaid_from_gas: u64,
    native_per_pubdata_byte: u64,
    intrinsic_gas: u64,
    intrinsic_computational_native: u64,
    intrinsic_pubdata: u64,
) -> Result<ResourcesForTx<S>, P::Error>
where
    S::Metadata: ZkSpecificPricingMetadata,
{
    // This is the real limit, which we later use to compute native_used.
    // From it, we discount intrinsic pubdata and then take the min
    // with the MAX_NATIVE_COMPUTATIONAL.
    // We do those operations in that order because the pubdata charge
    // isn't computational.
    // We can consider in the future to keep two limits, so that pubdata
    // is not charged from computational resource.
    // Note: for zero gas price, we use "unlimited native"
    let native_limit = if cfg!(feature = "unlimited_native") || free_native {
        u64::MAX - 1 // So any saturation below can not be subtracted from it
    } else {
        native_prepaid_from_gas
    };

    // Charge intrinsic pubdata
    let intrinsic_pubdata_overhead = native_per_pubdata_byte.saturating_mul(intrinsic_pubdata);
    let native_limit = match native_limit.checked_sub(intrinsic_pubdata_overhead) {
        Some(val) => val,
        None => P::handle_arithmetic_error(
            system,
            P::native_underflow_error("subtracting pubdata overhead"),
        )?,
    };

    // EVM tester requires high native limits, so for it we never hold off resources.
    // But for the real world, we bound the available resources.

    #[cfg(feature = "resources_for_tester")]
    let withheld = S::Resources::from_ergs(Ergs::empty());

    #[cfg(not(feature = "resources_for_tester"))]
    let (native_limit, withheld) = if native_limit <= MAX_NATIVE_COMPUTATIONAL {
        (native_limit, S::Resources::from_ergs(Ergs::empty()))
    } else {
        let withheld =
            <<S as zk_ee::system::SystemTypes>::Resources as Resources>::Native::from_computational(
                native_limit - MAX_NATIVE_COMPUTATIONAL,
            );

        (
            MAX_NATIVE_COMPUTATIONAL,
            S::Resources::from_native(withheld),
        )
    };

    // Charge intrinsic computational native
    let native_limit = match native_limit.checked_sub(intrinsic_computational_native) {
        Some(val) => val,
        None => P::handle_arithmetic_error(
            system,
            P::native_underflow_error("subtracting intrinsic computational native"),
        )?,
    };

    let native_limit =
        <<S as zk_ee::system::SystemTypes>::Resources as Resources>::Native::from_computational(
            native_limit,
        );

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

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L166-168)
```rust
pub struct ResourcesForEthereumTx<S: EthereumLikeTypes> {
    pub main_resources: S::Resources,
}
```

**File:** docs/double_resource_accounting.md (L17-21)
```markdown
The native resource models the offchain cost of processing a transaction. Currently, this is dominated by proving and publishing data. A good intuition for it is "how many RISC-V cycles it takes to prove a given computation".

If a transaction execution runs out of native resources, the entire transaction is reverted. If the same happens during transaction validation, the transaction is considered invalid.

The native resources are passed fully from frame to frame, a call cannot set a limit on how much of it the callee can spend.
```

**File:** zk_ee/src/system/constants.rs (L26-26)
```rust
pub const MAX_NATIVE_COMPUTATIONAL: u64 = 1 << 35;
```
