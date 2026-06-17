### Title
`gas_per_pubdata_limit` Not Enforced for L2 ZK Transactions — Users Pay More Than Expected for Pubdata - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

### Summary
The `gas_per_pubdata_limit` field in the ZKsync-specific ABI-encoded transaction format is documented as "the maximum gas the user is willing to pay for a byte of pubdata." It is enforced for L1→L2 transactions but is silently ignored for L2 ZK transactions (type `0x71`). When the block's pubdata price exceeds the user's stated limit, the transaction is included anyway, causing the user to pay more for pubdata than they consented to — or to have their transaction revert and lose the full gas limit.

### Finding Description

The `AbiEncodedTransaction` struct parses `gas_per_pubdata_limit` but marks it `#[allow(dead_code)]`: [1](#0-0) 

The `Transaction::gas_per_pubdata_limit()` accessor returns `U256::ZERO` for RLP-encoded L2 transactions and the actual value for ABI-encoded ones: [2](#0-1) 

For **L1→L2 transactions**, `gas_per_pubdata_limit` is correctly read and used to derive `native_per_pubdata`: [3](#0-2) 

For **L2 ZK transactions**, `validate_and_compute_fee_for_transaction` in `validation_impl.rs` computes `native_per_pubdata` exclusively from the block's `pubdata_price` and `native_price`, with no comparison against the user's `gas_per_pubdata_limit`: [4](#0-3) 

The only guard is an overflow check (triggering `PubdataPriceTooHigh` only if `pubdata_price / native_price` overflows `u64`), not a comparison with the user's stated limit: [5](#0-4) 

### Impact Explanation

A user submitting a ZK L2 transaction sets `gas_per_pubdata_limit = X` to cap their pubdata exposure. If the block's pubdata price `Y > X`:

1. The transaction is included without rejection.
2. Native resources are consumed at the higher rate `Y`, not the user's limit `X`.
3. **Scenario A (revert):** If pubdata costs exhaust the native budget, the transaction reverts post-execution. The user loses the full `gas_limit * gas_price` fee — more than they would have paid had the transaction been rejected at validation.
4. **Scenario B (success with deltaGas):** If the transaction succeeds, the `deltaGas` adjustment in `compute_gas_refund` charges additional EVM gas to cover the excess native consumption, increasing the effective fee beyond what the user expected: [6](#0-5) 

In both cases the user pays more than their stated `gas_per_pubdata_limit` consent allows.

### Likelihood Explanation

L1 pubdata prices fluctuate with Ethereum gas prices. A user who signs a transaction during low-fee conditions and has it included during a fee spike will have their `gas_per_pubdata_limit` silently ignored. This is a realistic, unprivileged scenario requiring no special access — any sequencer/operator including the transaction in a block with elevated pubdata pricing triggers it.

### Recommendation

In `validate_and_compute_fee_for_transaction` (ZK L2 path), after computing `native_per_pubdata`, derive the effective gas-per-pubdata and compare it against `transaction.gas_per_pubdata_limit()`. If the block's pubdata price exceeds the user's limit, reject the transaction with `InvalidTransaction::PubdataPriceTooHigh`, mirroring the enforcement already present for L1 transactions.

```rust
// After computing native_per_pubdata:
let gas_per_pubdata_limit = transaction.gas_per_pubdata_limit();
if !gas_per_pubdata_limit.is_zero() {
    // effective gas per pubdata = pubdata_price / gas_price (approx)
    let effective_gas_per_pubdata = pubdata_price
        .wrapping_div(gas_price.max(U256::ONE));
    require!(
        effective_gas_per_pubdata <= gas_per_pubdata_limit,
        TxError::Validation(InvalidTransaction::PubdataPriceTooHigh),
        system
    )?;
}
```

### Proof of Concept

1. User signs a ZK L2 transaction (type `0x71`) with `gas_per_pubdata_limit = 100` and `gas_limit = 500_000`, `max_fee_per_gas = 1000`.
2. Block is produced with `pubdata_price` such that effective gas-per-pubdata = `500` (5× the user's limit).
3. `validate_and_compute_fee_for_transaction` computes `native_per_pubdata` from the block price with no check against `100`.
4. Transaction is included; native resources are consumed at 5× the expected rate.
5. If the transaction writes storage (generating pubdata), it reverts post-execution due to insufficient native resources, and the user is charged the full `500_000 * 1000 = 500_000_000` wei — far more than they would have paid had the transaction been rejected at validation with a small intrinsic gas charge. [4](#0-3) [1](#0-0)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L77-81)
```rust
    // For L1->L2 transactions we always use the pubdata price provided by the transaction.
    // This is needed to ensure DDoS protection. All the excess expenditure
    // will be refunded to the user.
    let gas_per_pubdata = transaction.gas_per_pubdata_limit.read();

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

**File:** basic_bootloader/src/bootloader/transaction_flow/refund_calculation.rs (L69-80)
```rust
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
