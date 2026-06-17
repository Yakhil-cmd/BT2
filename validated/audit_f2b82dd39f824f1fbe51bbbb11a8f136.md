### Title
Unlimited Native Resource Allocation for Zero-Gas-Price L2 Transactions Enables Zero-Cost Block Stuffing - (File: `basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs`)

---

### Summary

When `eip1559_basefee = 0`, an L2 transaction with `gas_price = 0` and `value = 0` submitted from an account with zero balance passes all validation checks and receives an effectively unlimited native resource budget (`u64::MAX - 1`). An unprivileged attacker can craft a single transaction that consumes the entire block's native computational budget at zero cost, preventing all other transactions from being included in that block.

---

### Finding Description

In `create_resources_for_tx`, the `free_native` flag is used to bypass the normal native resource limit derivation: [1](#0-0) 

When `free_native = true`, `native_limit` is set to `u64::MAX - 1` — effectively unlimited — instead of being derived from the fee paid.

The `free_native` flag is set to `true` when `native_per_gas == 0`: [2](#0-1) 

For L2 transactions, `native_per_gas` is computed as `gas_price / native_price`. When `gas_price = 0`, `native_per_gas = 0`, and `free_native = true`: [3](#0-2) 

When `eip1559_basefee = 0`, a transaction with `max_fee_per_gas = 0` passes the basefee check. The balance check requires `total_required_balance = gas_price * gas_limit + value`. With both zero, any account — including one with zero balance — satisfies `0 ≥ 0`: [4](#0-3) 

The block-level native limit check in the ZK tx loop only rejects a transaction if it *exceeds* `MAX_NATIVE_COMPUTATIONAL`: [5](#0-4) 

A transaction that consumes exactly `MAX_NATIVE_COMPUTATIONAL` native resources passes this check and is committed, exhausting the block's entire native budget.

---

### Impact Explanation

An attacker with zero balance, when `eip1559_basefee = 0`, can submit a zero-cost L2 transaction calling a contract that performs many storage writes. Because the transaction's native limit is `u64::MAX - 1`, it can consume up to `MAX_NATIVE_COMPUTATIONAL` native resources in a single transaction. After this transaction is committed, no further transactions can be included in the block (`BlockNativeLimitReached`). The attacker pays no fee and requires no balance. This is a block-level resource exhaustion / DoS: legitimate transactions are excluded from the block at zero attacker cost, directly analogous to the external report's unbounded registration flooding.

---

### Likelihood Explanation

The attack requires `eip1559_basefee = 0`, which is an operator-set parameter. This is a valid production state (e.g., at chain genesis, during certain operator configurations, or if the basefee adjustment mechanism drives it to zero). The attacker needs no funds and no privileged access. The attack is trivially repeatable across consecutive blocks as long as `basefee = 0` persists. The existing test `test_gas_price_zero_fee_zero` confirms zero-gas-price transactions are accepted and execute normally under this condition: [6](#0-5) 

---

### Recommendation

1. **Bound native resources even for zero-gas-price transactions.** Instead of setting `native_limit = u64::MAX - 1` when `free_native = true`, cap it at `MAX_NATIVE_COMPUTATIONAL` (the block-level limit) or a configurable per-transaction native ceiling. This prevents a single zero-cost transaction from consuming the entire block's native budget.

2. **Enforce a minimum basefee floor.** The block metadata initialization should reject or warn when `eip1559_basefee = 0` in production mode, preventing the zero-gas-price path from being reachable by unprivileged senders. [1](#0-0) 

---

### Proof of Concept

```
1. Configure block context with eip1559_basefee = U256::ZERO.

2. Deploy a contract that performs MAX_NATIVE_COMPUTATIONAL / SSTORE_NATIVE_COST
   storage writes (e.g., a loop writing to 20 distinct slots as in the existing
   test_pubdata_native_calculation_overflow bytecode).

3. Create an attacker account with zero balance.

4. Submit an L2 EIP-1559 transaction:
     max_fee_per_gas = 0
     max_priority_fee_per_gas = 0
     gas_limit = block_gas_limit   (passes CallerGasLimitMoreThanBlock check)
     value = 0
     from = attacker (zero balance)
     to = deployed contract

5. Validation path:
   - gas_price = effective_gas_price(0, 0, basefee=0) = 0  → passes GasPriceLessThanBasefee
   - total_required_balance = 0 * gas_limit + 0 = 0 ≤ 0   → passes LackOfFundForMaxFee
   - native_per_gas = 0 / native_price = 0
   - free_native = true → native_limit = u64::MAX - 1

6. Execution: contract consumes ≈ MAX_NATIVE_COMPUTATIONAL native resources.

7. check_for_block_limits: computational_native_used == MAX_NATIVE_COMPUTATIONAL
   → NOT > MAX_NATIVE_COMPUTATIONAL → transaction is COMMITTED.

8. All subsequent transactions in the block receive BlockNativeLimitReached
   and are reverted. The block is sealed with only the attacker's transaction.
   Attacker paid zero fee.
```

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L324-349)
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L438-451)
```rust
    // Balance check - originator must cover fee prepayment plus whatever "value" it would like to send along
    let Some(total_required_balance) = transaction.required_balance() else {
        return Err(TxError::Validation(
            InvalidTransaction::OverflowPaymentInTransaction,
        ));
    };
    if total_required_balance > originator_account_data.nominal_token_balance.0 {
        return Err(TxError::Validation(
            InvalidTransaction::LackOfFundForMaxFee {
                fee: total_required_balance,
                balance: originator_account_data.nominal_token_balance.0,
            },
        ));
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/mod.rs (L68-93)
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
        // ZKsync OS-specific resources are not checked for evm tester
        system_log!(
            system,
            "Block pubdata limit reached, invalidating transaction\n"
        );
        Err(InvalidTransaction::BlockPubdataLimitReached)
    } else if !cfg!(feature = "resources_for_tester") && logs_used > MAX_NUMBER_OF_LOGS {
        // ZKsync OS-specific resources are not checked for evm tester
        system_log!(
            system,
            "Block logs limit reached, invalidating transaction\n"
        );
        Err(InvalidTransaction::BlockL2ToL1LogsLimitReached)
    } else {
        Ok(())
    }
```

**File:** tests/instances/transactions/src/lib.rs (L179-198)
```rust
fn test_gas_price_zero_fee_zero() {
    let mut tester = TestingFramework::new_with_randomized_tree();
    let block_context = BlockContext {
        eip1559_basefee: U256::ZERO,
        ..BlockContext::default()
    };
    let output = tester.run_block_of_erc20_with_fee(10, Some(block_context), 0);
    let res_0 = output
        .tx_results
        .first()
        .cloned()
        .expect("Must have first result")
        .expect("Must be valid");

    // Regression check, at some point txs with 0 gas price were returning 0 native used.
    assert!(
        res_0.native_used > 0,
        "Native used must be greater than zero"
    );
}
```
