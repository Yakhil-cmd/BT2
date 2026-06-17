### Title
Unfinalized Placeholder Constant `L1_TX_NATIVE_PRICE` Controls Native Resource Budget for All L1→L2 Transactions — (File: `basic_bootloader/src/bootloader/constants.rs`)

---

### Summary

`L1_TX_NATIVE_PRICE` is hardcoded to `10` with an explicit TODO comment acknowledging the value has not been finalized. This constant is the sole divisor used to convert an L1→L2 transaction's gas price into its native resource budget (`native_per_gas = gas_price / L1_TX_NATIVE_PRICE`). Because L1→L2 transactions cannot be invalidated (doing so would halt the priority queue), a miscalibrated value directly and irrecoverably distorts the native resource accounting for every priority transaction processed by the chain.

---

### Finding Description

In `basic_bootloader/src/bootloader/constants.rs`, the constant is declared as:

```rust
// Default native price for L1->L2 transactions.
// TODO (EVM-1157): find a reasonable value for it.
pub const L1_TX_NATIVE_PRICE: U256 = U256::from_limbs([10, 0, 0, 0]);
``` [1](#0-0) 

The TODO is not cosmetic. The documentation for the double-resource accounting model explicitly states: *"for L1→L2 transactions we use a code constant instead of one provided by operator"*, confirming that unlike L2 transactions (where `native_price` is operator-supplied per block), L1→L2 transactions are permanently bound to this single hardcoded value. [2](#0-1) 

In `process_l1_transaction.rs`, `prepare_and_check_resources` uses `L1_TX_NATIVE_PRICE` as the denominator to derive `native_per_gas`:

```rust
let native_price = L1_TX_NATIVE_PRICE;
// ...
u256_try_to_u64(&gas_price.div_ceil(native_price))
``` [3](#0-2) 

`native_per_gas` then feeds directly into `native_prepaid_from_gas = native_per_gas * gas_limit`, which becomes the transaction's native resource limit passed to `create_resources_for_tx`. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

Native resources model the off-chain proving cost ("how many RISC-V cycles it takes to prove a given computation"). The ratio `gas_price / L1_TX_NATIVE_PRICE` determines how many native cycles a transaction is budgeted.

- **If `L1_TX_NATIVE_PRICE = 10` is too low** relative to the actual proving cost per cycle: every L1→L2 transaction receives a native budget far exceeding what it economically paid for. An attacker submitting L1→L2 transactions with a high gas price and high gas limit gets a disproportionately large native resource allocation, consuming proving capacity without adequate compensation. Because L1→L2 transactions cannot be rejected (the code explicitly saturates rather than invalidates them to avoid halting the priority queue), there is no on-chain backstop.

- **If `L1_TX_NATIVE_PRICE = 10` is too high**: legitimate L1→L2 transactions run out of native resources mid-execution and revert, causing silent fund loss for depositors whose transactions fail after the L1 deposit is already committed.

Both directions represent a resource accounting bug with direct financial impact on either the protocol (subsidized proving) or users (failed deposits).

---

### Likelihood Explanation

The TODO comment `// TODO (EVM-1157): find a reasonable value for it.` is an explicit in-code acknowledgment that the value is a placeholder. The constant is already live in the production execution path for every L1→L2 priority transaction. Any L1→L2 transaction sender — an unprivileged actor — exercises this code path. No special access, governance role, or oracle manipulation is required.

---

### Recommendation

1. Resolve TODO `EVM-1157`: derive `L1_TX_NATIVE_PRICE` from a formally specified, benchmarked proving cost rather than an arbitrary placeholder.
2. Until resolved, document the known risk and add a compile-time or runtime assertion that the value has been reviewed against current prover benchmarks before deployment.
3. Consider making `L1_TX_NATIVE_PRICE` configurable via the same operator-supplied block metadata mechanism used for L2 transactions, so it can be updated without a protocol upgrade.

---

### Proof of Concept

1. Submit an L1→L2 priority transaction with `gas_price = 10_000` and `gas_limit = 10_000_000`.
2. The bootloader computes: `native_per_gas = ceil(10_000 / 10) = 1_000`.
3. `native_prepaid_from_gas = 1_000 * 10_000_000 = 10_000_000_000`.
4. This exceeds `MAX_NATIVE_COMPUTATIONAL = 2^35 ≈ 34_359_738_368`, so the excess is placed in `withheld` resources (still available for pubdata).
5. The transaction body runs with the maximum computational native budget (`2^35`) — the same budget as a transaction that paid 3× more on L2 — purely because `L1_TX_NATIVE_PRICE` is an unvalidated placeholder.
6. If the actual proving cost per cycle is, say, `100` instead of `10`, the transaction received 10× more proving budget than it paid for, with no mechanism to reject or penalize it. [1](#0-0) [6](#0-5) [7](#0-6)

### Citations

**File:** basic_bootloader/src/bootloader/constants.rs (L64-66)
```rust
// Default native price for L1->L2 transactions.
// TODO (EVM-1157): find a reasonable value for it.
pub const L1_TX_NATIVE_PRICE: U256 = U256::from_limbs([10, 0, 0, 0]);
```

**File:** docs/double_resource_accounting.md (L34-34)
```markdown
- `nativePrice` be a constant set by the operator, reflecting the "cost of processing a single cycle". Note: for L1->L2 transactions we use a code constant instead of one provided by operator.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L453-479)
```rust
    // For L1->L2 txs, we use a constant native price to avoid censorship.
    let native_price = L1_TX_NATIVE_PRICE;
    let native_per_gas = if is_priority_op {
        if gas_price.is_zero() {
            if Config::SIMULATION {
                u256_try_to_u64(&system.get_eip1559_basefee().div_ceil(native_price))
                    .unwrap_or_else(|| {
                        system_log!(
                            system,
                            "Native per gas calculation for L1 tx overflows, using saturated arithmetic instead");
                        u64::MAX
                    })
            } else {
                FREE_L1_TX_NATIVE_PER_GAS
            }
        } else {
            u256_try_to_u64(&gas_price.div_ceil(native_price)).unwrap_or_else(|| {
                system_log!(
                    system,
                    "Native per gas calculation for L1 tx overflows, using saturated arithmetic instead");
                u64::MAX
            })
        }
    } else {
        // Upgrade txs are paid by the protocol, so we use a fixed native per gas
        FREE_L1_TX_NATIVE_PER_GAS
    };
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L490-496)
```rust
    let native_prepaid_from_gas = native_per_gas.checked_mul(gas_limit)
        .unwrap_or_else(|| {
            system_log!(
                system,
                "Native prepaid from gas calculation for L1 tx overflows, using saturated arithmetic instead");
                u64::MAX
        });
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L324-380)
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
```
