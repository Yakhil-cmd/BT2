### Title
`gasPerPubdataByteLimit` Slippage Protection Silently Ignored for L2 ZK Transactions - (`basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs`, `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

### Summary

ZKsync OS parses the `gasPerPubdataByteLimit` field from ZK (type `0x71`) L2 transactions but never enforces it during validation. The field is explicitly annotated `#[allow(dead_code)]`. Instead, the bootloader unconditionally derives `native_per_pubdata` from the block-level oracle prices. A user who sets `gasPerPubdataByteLimit` to cap their pubdata exposure receives no protection: if the block's pubdata price is higher than their limit, the transaction is still included, reverts post-execution, and the user loses their full gas limit.

### Finding Description

In `AbiEncodedTransaction`, the field is parsed but dead:

```rust
/// The maximum amount of gas the user is willing to pay for a byte of pubdata.
#[allow(dead_code)]
pub gas_per_pubdata_limit: ParsedValue<u32>,
``` [1](#0-0) 

In `Transaction::gas_per_pubdata_limit()`, the value is accessible:

```rust
pub fn gas_per_pubdata_limit(&self) -> U256 {
    match self {
        Self::Rlp(_) => U256::ZERO,
        Self::Abi(tx) => U256::from(tx.gas_per_pubdata_limit.read()),
    }
}
``` [2](#0-1) 

But in `validate_and_compute_fee_for_transaction` (the ZK L2 validation path), `native_per_pubdata` is computed exclusively from block-level oracle prices — `transaction.gas_per_pubdata_limit()` is never called:

```rust
let pubdata_price = system.get_pubdata_price();
let native_price = system.get_native_price();
// ...
let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
    .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
``` [3](#0-2) 

By contrast, L1→L2 transactions **do** use the user-supplied limit:

```rust
// For L1->L2 transactions we always use the pubdata price provided by the transaction.
let gas_per_pubdata = transaction.gas_per_pubdata_limit.read();
``` [4](#0-3) 

The asymmetry is intentional for L1 transactions (DDoS protection) but leaves L2 ZK transactions with a documented-but-unenforced protection field.

### Impact Explanation

When pubdata is expensive enough that the user's gas budget cannot cover it, the transaction reverts post-execution and the user loses their **full gas limit**. This is confirmed by the existing test:

```rust
assert_eq!(
    tx_result.gas_used, gas_limit,
    "Tx reverted by post-execution pubdata charging must consume full gas limit"
);
``` [5](#0-4) 

A user who set `gasPerPubdataByteLimit = X` to avoid exactly this scenario receives no protection. They pay `gas_price × gas_limit` for a reverted transaction, more per unit of useful execution than they consented to — the direct analog of the bonding-curve slippage: paying the full price for fewer (zero) tokens/execution.

**Impact: High** — direct loss of user gas funds with no recourse.

### Likelihood Explanation

The pubdata price is a block-level oracle value that can change between transaction submission and inclusion. A natural pubdata price spike (e.g., L1 calldata cost increase) or a sequencer that sets a high `pubdata_price` in the block metadata can trigger this. The user has no on-chain mechanism to protect themselves because their stated limit is ignored.

**Likelihood: Low** — requires pubdata price to spike or a sequencer acting against user interest, but no privileged key or governance attack is needed; the pubdata price is a normal block parameter.

### Recommendation

In `validate_and_compute_fee_for_transaction`, after computing the block-level `native_per_pubdata`, compare it against the transaction's `gas_per_pubdata_limit`. If the block's effective gas-per-pubdata exceeds the user's stated limit, reject the transaction with a new `InvalidTransaction::PubdataLimitExceeded` error, analogous to how `BaseFeeGreaterThanMaxFee` protects against gas price spikes:

```rust
let tx_gas_per_pubdata_limit = transaction.gas_per_pubdata_limit();
if !tx_gas_per_pubdata_limit.is_zero() {
    let effective_gas_per_pubdata = pubdata_price / native_price * native_per_gas_u256;
    require!(
        effective_gas_per_pubdata <= tx_gas_per_pubdata_limit,
        InvalidTransaction::PubdataLimitExceeded,
        system
    )?;
}
```

Remove the `#[allow(dead_code)]` annotation from `gas_per_pubdata_limit` once the check is in place.

### Proof of Concept

1. User submits a ZK (type `0x71`) transaction with `gasPerPubdataByteLimit = 100` and `gas_limit = 250_000`, `max_fee_per_gas = 1000`.
2. Sequencer sets `pubdata_price = 700_000`, `native_price = 1` in the block — effective gas-per-pubdata far exceeds 100.
3. Bootloader ignores `gasPerPubdataByteLimit`; computes `native_per_pubdata = 700_000`.
4. Transaction executes, writes storage (generating pubdata), then fails the post-execution pubdata check.
5. Transaction is marked reverted; `gas_used = gas_limit = 250_000`.
6. User pays `1000 × 250_000 = 250,000,000` wei for zero useful execution, despite having set a pubdata limit of 100 gas/byte to prevent exactly this outcome.

The existing test `test_l2_tx_not_enough_native_for_pubdata_uses_full_gas_limit` in `tests/instances/transactions/src/native_charging.rs` already demonstrates steps 4–6 with `pubdata_price = 700_000`. [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L49-51)
```rust
    /// The maximum amount of gas the user is willing to pay for a byte of pubdata.
    #[allow(dead_code)]
    pub gas_per_pubdata_limit: ParsedValue<u32>,
```

**File:** basic_bootloader/src/bootloader/transaction/mod.rs (L150-156)
```rust
    /// Returns the gas per pubdata limit.
    pub fn gas_per_pubdata_limit(&self) -> U256 {
        match self {
            Self::Rlp(_) => U256::ZERO,
            Self::Abi(tx) => U256::from(tx.gas_per_pubdata_limit.read()),
        }
    }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L106-143)
```rust
    let pubdata_price = system.get_pubdata_price();
    let native_price = system.get_native_price();

    let gas_price = if transaction.is_service() {
        // Service transactions do not pay gas fees,
        // their gas price is allowed to be < block base fee.
        U256::ZERO
    } else {
        get_gas_price::<S, Config>(
            system,
            transaction.max_fee_per_gas(),
            transaction.max_priority_fee_per_gas(),
        )?
    };

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

    // We checked native_price != 0 above
    let native_per_pubdata = u256_try_to_u64(&pubdata_price.wrapping_div(native_price))
        .ok_or(TxError::Validation(InvalidTransaction::PubdataPriceTooHigh))?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L77-80)
```rust
    // For L1->L2 transactions we always use the pubdata price provided by the transaction.
    // This is needed to ensure DDoS protection. All the excess expenditure
    // will be refunded to the user.
    let gas_per_pubdata = transaction.gas_per_pubdata_limit.read();
```

**File:** tests/instances/transactions/src/native_charging.rs (L167-237)
```rust
#[test]
fn test_l2_tx_not_enough_native_for_pubdata_uses_full_gas_limit() {
    let wallet = testing_signer(0);
    let from = wallet.address();
    let gas_limit = 250_000;
    let bytecode = hex::decode(
        "602a600052600160005560016001556001600255600160035560016004556001600555600160065560016007556001600855600160095560206000f3",
    )
    .unwrap();

    let make_tx = || {
        let tx = TxEip1559 {
            chain_id: 37u64,
            nonce: 0,
            max_fee_per_gas: 1000,
            max_priority_fee_per_gas: 1000,
            gas_limit,
            to: TxKind::Call(TO),
            value: U256::ZERO,
            input: Default::default(),
            access_list: Default::default(),
        };
        ZKsyncTxEnvelope::from_eth_tx(tx, wallet.clone())
    };

    // Control execution should succeed, so the failing case below is specific to
    // post-execution pubdata charging.
    let control_context = BlockContext {
        eip1559_basefee: U256::from(1000),
        native_price: U256::ONE,
        pubdata_price: U256::ONE,
        ..Default::default()
    };
    let mut control_tester = TestingFramework::new()
        .with_evm_contract(TO, &bytecode)
        .with_balance(from, U256::from(1_000_000_000_000_000_u64))
        .with_block_context(control_context);
    let control_output = control_tester.execute_block(vec![make_tx()]);
    let control_tx = control_output.tx_results[0]
        .as_ref()
        .expect("Control tx should be processed");
    assert!(
        control_tx.is_success(),
        "Control tx must succeed with regular pubdata pricing"
    );

    // Expensive pubdata causes a post-execution revert due to insufficient native.
    let expensive_pubdata_context = BlockContext {
        eip1559_basefee: U256::from(1000),
        native_price: U256::ONE,
        pubdata_price: U256::from(700_000u64),
        ..Default::default()
    };
    let mut tester = TestingFramework::new()
        .with_evm_contract(TO, &bytecode)
        .with_balance(from, U256::from(1_000_000_000_000_000_u64))
        .with_block_context(expensive_pubdata_context);
    let output = tester.execute_block(vec![make_tx()]);
    let tx_result = output.tx_results[0]
        .as_ref()
        .expect("Tx should be processed even when reverted");

    assert!(
        !tx_result.is_success(),
        "Tx should revert when pubdata cannot be paid after execution"
    );
    assert_eq!(
        tx_result.gas_used, gas_limit,
        "Tx reverted by post-execution pubdata charging must consume full gas limit"
    );
}
```
