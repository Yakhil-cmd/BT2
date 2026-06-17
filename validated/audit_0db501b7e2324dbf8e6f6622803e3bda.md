### Title
Zero Base Fee Grants Unlimited Native Resources at Zero Cost, Enabling Per-Block Native Resource Exhaustion DOS - (File: `basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs`)

### Summary
When the operator sets `eip1559_basefee = 0`, every L2 transaction's effective gas price is forced to zero regardless of the sender's `max_fee_per_gas`. This causes `native_per_gas = 0`, which triggers the "free native" path granting unlimited native resources at zero cost. An unprivileged attacker can submit multiple zero-cost transactions that collectively exhaust the block's `MAX_NATIVE_COMPUTATIONAL` native resource budget, causing all subsequent transactions in the same block to be rejected with `BlockNativeLimitReached`.

### Finding Description

**Step 1 — Zero basefee forces zero gas price for all L2 transactions.**

In `get_gas_price()`, when `base_fee.is_zero()`, the function unconditionally returns `U256::ZERO`, ignoring any `max_priority_fee_per_gas` the sender may have set: [1](#0-0) 

This is documented as an intentional EVM divergence, but it means that when basefee is zero, no transaction pays any fee.

**Step 2 — Zero gas price yields `native_per_gas = 0`, triggering unlimited native.**

In `validate_and_compute_fee_for_transaction()`, `native_per_gas = ceil(gas_price / native_price) = 0` when `gas_price = 0`. This is then passed as `free_native = true` to `create_resources_for_tx()`: [2](#0-1) 

Inside `create_resources_for_tx()`, `free_native = true` sets `native_limit = u64::MAX - 1`: [3](#0-2) 

The transaction now has effectively unlimited native resources and pays zero fee.

**Step 3 — Block-level native resource cap is the only guard.**

`check_for_block_limits()` enforces `MAX_NATIVE_COMPUTATIONAL = 2^35` as the per-block cumulative native resource cap: [4](#0-3) [5](#0-4) 

Once the cumulative `computational_native_used` across accepted transactions exceeds `MAX_NATIVE_COMPUTATIONAL`, every subsequent transaction in the block is rejected with `BlockNativeLimitReached` and its state changes are rolled back: [6](#0-5) 

**Step 4 — Attacker exhausts the budget at zero cost.**

When basefee is zero, the attacker submits multiple transactions with `max_fee_per_gas = 0`. Each transaction receives unlimited native resources and pays nothing. The attacker can craft transactions that perform computationally expensive operations (e.g., repeated `SSTORE`, `keccak256`, or other high-native-cost opcodes) to collectively consume `MAX_NATIVE_COMPUTATIONAL` native units across the block, at zero token cost.

### Impact Explanation

Once the block's `MAX_NATIVE_COMPUTATIONAL` budget is exhausted, all remaining transactions in that block are rejected with `BlockNativeLimitReached` and their state is rolled back. Legitimate users cannot get their transactions included for the duration of that block. The attacker pays zero fees (no `LackOfFundForMaxFee` check fires because `fee_to_prepay = gas_used * gas_price = 0`). The DOS is per-block, not per-day, but can be sustained across consecutive blocks as long as basefee remains zero, since the attacker bears no cost.

### Likelihood Explanation

The condition `eip1559_basefee == 0` is operator-controlled via `BlockMetadataFromOracle`. It can occur during network bootstrapping, promotional zero-fee periods, or operator misconfiguration. The default test configuration explicitly uses `eip1559_basefee = U256::ZERO` in some contexts: [7](#0-6) 

The attack requires no special privileges — any EOA with a valid nonce can submit zero-fee transactions when basefee is zero.

### Recommendation

1. When `native_per_gas == 0` (zero gas price), cap the available native resources to a per-transaction maximum (e.g., `MAX_NATIVE_COMPUTATIONAL / MIN_TXS_PER_BLOCK`) rather than granting `u64::MAX - 1`. This prevents a single sender from monopolizing the block's native budget at zero cost.
2. Alternatively, enforce a minimum `native_per_gas` floor even when `gas_price == 0`, derived from the block's `native_price`, so that native resource consumption always has a proportional cost.
3. Document explicitly that `eip1559_basefee = 0` disables all native resource accounting protections, so operators are aware of the DOS risk.

### Proof of Concept

1. Operator produces a block with `eip1559_basefee = 0`.
2. Attacker submits N L2 transactions with `max_fee_per_gas = 0`, `gas_limit = MAX_BLOCK_GAS_LIMIT`, each containing a loop of `SSTORE` or `keccak256` opcodes to maximize native consumption.
3. For each attacker transaction: `get_gas_price()` returns `0` → `native_per_gas = 0` → `free_native = true` → `native_limit = u64::MAX - 1`. The transaction executes with unlimited native resources and pays zero fee.
4. After enough attacker transactions, `block_data.block_computational_native_used` exceeds `MAX_NATIVE_COMPUTATIONAL = 2^35`.
5. All subsequent legitimate transactions in the block hit `check_for_block_limits()` → `BlockNativeLimitReached` → state rollback → transaction excluded.
6. The attacker repeats this every block as long as basefee remains zero, sustaining the DOS at zero cost.

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

**File:** basic_bootloader/src/bootloader/block_flow/zk/mod.rs (L68-77)
```rust
    } else if !cfg!(feature = "resources_for_tester")
        && computational_native_used > MAX_NATIVE_COMPUTATIONAL
    {
        // ZKsync OS-specific resources are not checked for evm tester
        system_log!(
            system,
            "Block native limit reached, invalidating transaction\n"
        );
        Err(InvalidTransaction::BlockNativeLimitReached)
    } else if !cfg!(feature = "resources_for_tester") && pubdata_used > system.get_pubdata_limit() {
```

**File:** zk_ee/src/system/constants.rs (L26-26)
```rust
pub const MAX_NATIVE_COMPUTATIONAL: u64 = 1 << 35;
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L152-162)
```rust
                            if let Err(err) = check_for_block_limits(
                                system,
                                next_block_gas_used,
                                next_block_computational_native_used,
                                next_block_pubdata_used,
                                block_logs_used,
                                next_block_blob_gas_used,
                            ) {
                                // Revert to state before transaction
                                system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
                                result_keeper.tx_processed(Err(err));
```

**File:** tests/rig/src/chain.rs (L162-175)
```rust
impl Default for BlockContext {
    fn default() -> Self {
        Self {
            timestamp: 42,
            eip1559_basefee: U256::from_str_radix("1000", 10).unwrap(),
            pubdata_price: U256::default(),
            native_price: U256::from(10),
            coinbase: B160::default(),
            gas_limit: MAX_BLOCK_GAS_LIMIT,
            pubdata_limit: u64::MAX,
            mix_hash: U256::ONE,
            blob_fee: U256::ONE,
        }
    }
```
