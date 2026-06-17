### Title
Operator-Set `native_price = 0` in `BlockMetadataFromOracle` Implicitly Terminates the Entire Block, Locking All L2 User Transactions - (`basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs`)

### Summary
The `native_price` field in `BlockMetadataFromOracle` is an operator-controlled block-level parameter. If the operator sets `native_price = 0`, the ZK transaction validation path returns an `internal_error!` rather than a graceful per-transaction validation error. Unlike a validation error — which only skips the offending transaction and allows the block to continue — an internal error causes the entire ZK transaction loop to terminate immediately, blocking every L2 transaction in the block.

### Finding Description
`BlockMetadataFromOracle` carries `native_price` as a plain `U256` field with no lower-bound constraint enforced at metadata-initialization time. [1](#0-0) 

The ZK metadata initialization only checks that `gas_limit` does not exceed a maximum; it performs no validation on `native_price`: [2](#0-1) 

During per-transaction validation, `validate_and_compute_fee_for_transaction` reads `native_price` and immediately returns an `internal_error!` if it is zero: [3](#0-2) 

In the ZK transaction loop, a `TxError::Internal` is handled differently from a `TxError::Validation`. A validation error reverts only the current transaction and records it as invalid; an internal error propagates out of the loop with `return Err(err)`, terminating block execution entirely: [4](#0-3) 

By contrast, a validation error is handled gracefully: [5](#0-4) 

The `native_price` value flows directly from the operator-supplied `BlockContext` into `BlockMetadataFromOracle` with no sanitization: [6](#0-5) 

### Impact Explanation
When `native_price = 0` is supplied in the block metadata, the first non-service L2 transaction processed causes `validate_and_compute_fee_for_transaction` to return `TxError::Internal`. The ZK tx loop propagates this as a fatal block-level error, aborting all remaining transaction processing. Every user transaction in the block is silently dropped — not recorded as a failed transaction, but simply never processed. Funds that users intended to move (transfers, withdrawals, contract interactions) are frozen for the duration of the affected block. The operator must issue a corrected block with `native_price > 0` to resume normal operation.

This is a more severe implicit lock than the original report's pattern: rather than blocking only users with outstanding debt, it blocks every L2 user in the block, and the mechanism (an `internal_error!` escalating to block termination) is entirely undocumented as a "transaction freeze" primitive.

### Likelihood Explanation
The operator controls `native_price` directly via the block context oracle. A value of `0` could be set intentionally (e.g., attempting to offer free transactions) or accidentally (e.g., a misconfigured sequencer, a default-zero value in a new deployment, or a bug in the fee-oracle pipeline). The `BlockContext::default()` in the test rig sets `native_price = U256::from(10)`, confirming that `0` is not a protected sentinel — it is simply an unvalidated input. There is no on-chain governance delay; the operator can correct the value in the next block, but all transactions in the affected block are already lost.

### Recommendation
Add a lower-bound check for `native_price` in the ZK metadata initialization, analogous to the existing upper-bound check on `gas_limit`:

```rust
// In basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs
if metadata.block_gas_limit() > MAX_BLOCK_GAS_LIMIT
    || metadata.individual_tx_gas_limit() > MAX_TX_GAS_LIMIT
    || metadata.native_price().is_zero()          // <-- add this
{
    return Err(internal_error!("invalid block metadata"));
}
```

Alternatively, change the `native_price.is_zero()` branch in `validate_and_compute_fee_for_transaction` to return a `TxError::Validation` (e.g., `InvalidTransaction::NativePriceIsZero`) so that only the individual transaction is rejected and the block continues processing.

### Proof of Concept
1. Construct a `BlockMetadataFromOracle` with `native_price = U256::ZERO` (all other fields valid).
2. Submit any standard EIP-1559 L2 transaction.
3. `validate_and_compute_fee_for_transaction` reaches line 122 of `validation_impl.rs`, evaluates `native_price.is_zero() == true`, and returns `Err(internal_error!("Native price cannot be 0").into())` — a `TxError::Internal`.
4. The ZK tx loop at line 108 of `tx_loop.rs` matches `Err(TxError::Internal(err))` and executes `return Err(err)`, terminating the entire block.
5. All subsequent transactions in the block are never processed; no `tx_processed` result is recorded for them. [7](#0-6) [4](#0-3) [8](#0-7) [2](#0-1)

### Citations

**File:** zk_ee/src/system/metadata/zk_metadata.rs (L114-132)
```rust
pub struct BlockMetadataFromOracle {
    // Chain id is temporarily also added here (so that it can be easily passed from the oracle)
    // long term, we have to decide whether we want to keep it here, or add a separate oracle
    // type that would return some 'chain' specific metadata (as this class is supposed to hold block metadata only).
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hashes: BlockHashes,
    pub timestamp: u64,
    pub eip1559_basefee: U256,
    pub pubdata_price: U256,
    pub native_price: U256,
    pub coinbase: B160,
    pub gas_limit: u64,
    pub pubdata_limit: u64,
    /// Source of randomness, currently holds the value
    /// of prevRandao.
    pub mix_hash: U256,
    pub blob_fee: U256,
}
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/metadata_op.rs (L27-31)
```rust
        if metadata.block_gas_limit() > MAX_BLOCK_GAS_LIMIT
            || metadata.individual_tx_gas_limit() > MAX_TX_GAS_LIMIT
        {
            return Err(internal_error!("block or tx gas limit is too high"));
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L106-124)
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
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L107-113)
```rust
                    match tx_result {
                        Err(TxError::Internal(err)) => {
                            system_log!(system, "Tx execution result: Internal error = {err:?}\n",);
                            // Finish the frame opened before processing the tx
                            system.finish_global_frame(None)?; // TODO should we use pre_tx_rollback_handle here?
                            return Err(err);
                        }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L114-122)
```rust
                        Err(TxError::Validation(err)) => {
                            system_log!(
                                system,
                                "Tx execution result: Validation error = {err:?}\n",
                            );
                            // Revert to state before transaction
                            system.finish_global_frame(Some(&pre_tx_rollback_handle))?;
                            result_keeper.tx_processed(Err(err));
                        }
```

**File:** forward_system/src/run/convert.rs (L81-98)
```rust
impl FromInterface<BlockContext> for BlockMetadataFromOracle {
    fn from_interface(value: BlockContext) -> Self {
        BlockMetadataFromOracle {
            chain_id: value.chain_id,
            block_number: value.block_number,
            block_hashes: BlockHashes(value.block_hashes.0),
            timestamp: value.timestamp,
            eip1559_basefee: value.eip1559_basefee,
            pubdata_price: value.pubdata_price,
            native_price: value.native_price,
            coinbase: ruint::aliases::B160::from_alloy(value.coinbase),
            gas_limit: value.gas_limit,
            pubdata_limit: value.pubdata_limit,
            mix_hash: value.mix_hash,
            blob_fee: value.blob_fee,
        }
    }
}
```
