### Title
Unguarded U256 Overflow in `gas_price * gas_limit` Causes Permanent Block Processing Failure — (File: `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

In `process_l1_transaction`, the multiplication `gas_price.checked_mul(U256::from(gas_limit))` at line 128–130 is not guarded against U256 overflow. If an L1 transaction carries a `max_fee_per_gas` value large enough to overflow when multiplied by `gas_limit`, the function returns `internal_error!("gp*gl")`, which propagates as a fatal `BootloaderSubsystemError` and permanently halts block processing. Because L1 transactions cannot be invalidated, the block is permanently stuck.

---

### Finding Description

`process_l1_transaction` reads two user-controlled fields from the L1 transaction:

- `gas_price` — a raw `U256` from `transaction.max_fee_per_gas.read()`
- `gas_limit` — a `u64` from `transaction.gas_limit.read()` [1](#0-0) 

It then computes:

```rust
let tx_internal_cost = gas_price
    .checked_mul(U256::from(gas_limit))
    .ok_or(internal_error!("gp*gl"))?;
``` [2](#0-1) 

`U256::MAX ≈ 2^256 − 1`. With `gas_limit = u64::MAX ≈ 2^64`, the multiplication overflows whenever `gas_price > U256::MAX / u64::MAX ≈ 2^192`. When it does, `checked_mul` returns `None`, `ok_or` converts it to `internal_error!("gp*gl")`, and the `?` operator propagates it as a `BootloaderSubsystemError`.

The surrounding code explicitly acknowledges that L1 transactions cannot be invalidated and that `prepare_and_check_resources` must handle all arithmetic errors gracefully via saturation: [3](#0-2) 

`prepare_and_check_resources` does exactly this — it saturates `native_per_gas` to `u64::MAX` on overflow: [4](#0-3) 

But the `gas_price * gas_limit` check at line 128–130 is placed **after** `prepare_and_check_resources` returns successfully, and it does **not** follow the same saturation pattern. It returns a fatal error instead.

The `BootloaderSubsystemError` propagates through `process_transaction`: [5](#0-4) 

via the `From` impl: [6](#0-5) 

and ultimately reaches `run_forward`, which panics on any `BootloaderSubsystemError`: [7](#0-6) 

A second identical overflow exists in the success-path refund calculation at line 329–330, but it is only reachable if the first check at line 128–130 already passed (same operands), so the primary trigger is line 128–130. [8](#0-7) 

---

### Impact Explanation

An attacker who can submit an L1→L2 priority transaction with `max_fee_per_gas > 2^192` and any non-zero `gas_limit` will cause `process_l1_transaction` to return a fatal `BootloaderSubsystemError`. Because L1 transactions cannot be invalidated or skipped, the bootloader cannot continue processing the block. The forward system panics and the block is permanently stuck — a complete, irreversible DoS of ZKsync OS block production for that block.

---

### Likelihood Explanation

The L1 bridge contract may reject transactions where `gas_price * gas_limit` overflows in Solidity 0.8+ checked arithmetic. However:

1. The ZKsync OS code itself explicitly states it must tolerate malformed L1 transactions (comment at line 100–104), yet fails to do so here.
2. Any future change to L1 validation logic, a bridge upgrade, or a cross-chain relay that does not enforce this bound would expose the path.
3. The threshold (`gas_price > 2^192`) is reachable with a standard U256 field — no special privilege is required beyond the ability to submit an L1→L2 transaction.
4. The analogous overflow in `native_per_gas` is already handled with saturation (test `test_l1_tx_gas_price_overflow_native_per_gas` exists), confirming the threat model is understood — but this specific multiplication was missed. [9](#0-8) 

---

### Recommendation

Apply the same saturation pattern already used in `prepare_and_check_resources`. Replace the hard `internal_error!` with a saturating cap or a graceful log-and-continue, consistent with `L1ResourcesPolicy::handle_arithmetic_error`: [10](#0-9) 

Concretely, cap `gas_price` to a safe maximum before the multiplication, or use `gas_price.saturating_mul(U256::from(gas_limit))` and treat the saturated value as the cost, mirroring the existing resilience logic for L1 transactions.

---

### Proof of Concept

1. Craft an L1→L2 priority transaction with:
   - `max_fee_per_gas = (U256::MAX / U256::from(u64::MAX)) + U256::ONE` (≈ 2^192 + 1)
   - `gas_limit = u64::MAX`
   - `reserved[0]` (total deposited) set to any value (the overflow fires before the deposit check)

2. Submit the transaction through the L1 bridge.

3. When the ZKsync OS bootloader processes the block containing this transaction, execution reaches line 128–130:
   ```rust
   let tx_internal_cost = gas_price          // ≈ 2^192 + 1
       .checked_mul(U256::from(gas_limit))   // u64::MAX ≈ 2^64
       .ok_or(internal_error!("gp*gl"))?;   // overflows → Err
   ```

4. `internal_error!("gp*gl")` is returned as `BootloaderSubsystemError`, propagates through `process_transaction` as `TxError::Internal`, reaches `run_forward`, and causes a panic.

5. Block processing halts permanently. No subsequent transactions in the block can be processed. [11](#0-10)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L68-80)
```rust
    let gas_limit = transaction.gas_limit.read();

    // The invariant that the user deposited more than the value needed
    // for the transaction must be enforced on L1, but we double-check it here
    // Note, that for now the property of block.base <= tx.maxFeePerGas does not work
    // for L1->L2 transactions. For now, these transactions are processed with the same gasPrice
    // they were provided on L1. In the future, we may apply a new logic for it.
    let gas_price = transaction.max_fee_per_gas.read();

    // For L1->L2 transactions we always use the pubdata price provided by the transaction.
    // This is needed to ensure DDoS protection. All the excess expenditure
    // will be refunded to the user.
    let gas_per_pubdata = transaction.gas_per_pubdata_limit.read();
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L100-104)
```rust
    // Compute resource and fee information, making sure we handle
    // all possible validation errors carefully.
    // L1 transactions cannot be invalidated. Therefore, the following
    // function makes sure L1 transactions are processable even when
    // some checks that should be performed by the L1 don't hold.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L128-137)
```rust
    let tx_internal_cost = gas_price
        .checked_mul(U256::from(gas_limit))
        .ok_or(internal_error!("gp*gl"))?;
    let value = transaction.value.read();
    let total_deposited = transaction.reserved[0].read();
    require_internal!(
        total_deposited >= tx_internal_cost,
        "Deposited amount too low",
        system
    )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L328-330)
```rust
        let prepaid_fee = gas_price
            .checked_mul(U256::from(transaction.gas_limit.read()))
            .ok_or(internal_error!("gp*gl"))?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L469-475)
```rust
            u256_try_to_u64(&gas_price.div_ceil(native_price)).unwrap_or_else(|| {
                system_log!(
                    system,
                    "Native per gas calculation for L1 tx overflows, using saturated arithmetic instead");
                u64::MAX
            })
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/process_transaction.rs (L44-53)
```rust
                    let r = F::process_l1_transaction::<Config>(
                        system,
                        system_functions,
                        memories,
                        zk_tx,
                        true,
                        tracer,
                        validator,
                    )?;
                    Ok(r)
```

**File:** basic_bootloader/src/bootloader/errors.rs (L141-145)
```rust
impl From<BootloaderSubsystemError> for TxError {
    fn from(v: BootloaderSubsystemError) -> Self {
        Self::Internal(v)
    }
}
```

**File:** forward_system/src/system/bootloader.rs (L27-31)
```rust
    if let Err(err) =
        ForwardBootloader::run_prepared::<Config>(oracle, &mut (), result_keeper, tracer, validator)
    {
        panic!("Forward run failed with: {err}")
    };
```

**File:** tests/instances/transactions/src/l1_tx_resilience.rs (L69-117)
```rust
/// Test that an L1 transaction with a gas price that would overflow the
/// native_per_gas calculation is processed gracefully.
///
/// The calculation is: native_per_gas = gas_price.div_ceil(L1_TX_NATIVE_PRICE)
/// where L1_TX_NATIVE_PRICE = 10. To overflow u64, gas_price needs to be
/// > u64::MAX * 10.
///
/// Prior to the resilience changes, this would fail with
/// InvalidTransaction::NativeResourcesAreTooExpensive. Now, u64::MAX is used
/// via saturating arithmetic.
#[test]
fn test_l1_tx_gas_price_overflow_native_per_gas() {
    let from = address!("1234000000000000000000000000000000000000");
    let to = common_target_address();

    // L1_TX_NATIVE_PRICE = 10
    // To overflow u64 in native_per_gas calculation: gas_price / 10 > u64::MAX
    // So gas_price > u64::MAX * 10
    let overflow_gas_price = u128::from(u64::MAX) * 11;

    let tx = L1TxBuilder::new()
        .from(from)
        .to(to)
        .gas_price(overflow_gas_price)
        .gas_limit(100_000)
        .value(alloy::primitives::U256::from(100))
        .build()
        .into();

    let mut tester =
        TestingFramework::new().with_balance(from, U256::from(1_000_000_000_000_000_u64));

    // The block should complete without panicking (no internal error)
    let result = tester.execute_block_no_panic(vec![tx]);
    assert!(
        result.is_ok(),
        "Block should complete without internal error, got: {:?}",
        result.err()
    );

    // The transaction should be processed (L1 txs cannot be invalidated)
    let output = result.unwrap();
    let tx_result = output.tx_results.first().expect("Should have tx result");
    assert!(
        tx_result.is_ok(),
        "L1 tx should be processed (not rejected with validation error), got: {:?}",
        tx_result
    );
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/gas_helpers.rs (L99-125)
```rust
    fn handle_arithmetic_error(
        system: &mut System<S>,
        error: Self::ArithmeticError,
    ) -> Result<u64, Self::Error> {
        match error {
            L1ArithmeticError::NativeUnderflow { operation } => {
                system_log!(
                    system,
                    "Native underflow during {}, saturating to 0 for L1 tx",
                    operation
                );
                Ok(0)
            }
            L1ArithmeticError::IntrinsicGasOverflow {
                intrinsic_overhead,
                gas_limit,
            } => {
                system_log!(
                    system,
                    "Gas limit {} < intrinsic gas {} for L1 tx, saturating to 0",
                    gas_limit,
                    intrinsic_overhead
                );
                Ok(0)
            }
        }
    }
```
