### Title
`tx_number` u32→u16 Truncation in L2→L1 Log Encoding Corrupts Log Merkle Root - (File: `zk_ee/src/common_structs/logs_storage.rs`)

### Summary

`GenericLogContent` stores `tx_number` as `u32`, but the conversion to `L2ToL1Log` silently truncates it to `u16` via `m.tx_number as u16`. The block-level transaction counter `current_transaction_number` (also `u32`) is incremented without any upper-bound check against `u16::MAX` (65535), and no block-limit guard prevents the counter from exceeding that threshold. If a block contains more than 65535 transactions, every subsequent L2→L1 log will carry a wrapped, incorrect `tx_number_in_block`, corrupting the L2→L1 log Merkle tree root that is committed to in the block's public inputs.

### Finding Description

`ZKBasicBlockDataKeeper.current_transaction_number` is a `u32` incremented unconditionally at each successful transaction:

```rust
block_data.current_transaction_number += 1;  // tx_loop.rs:212
```

`check_for_block_limits` enforces gas, native, pubdata, and log-count ceilings, but imposes **no ceiling on the transaction count itself**:

```rust
fn check_for_block_limits(...) -> Result<(), InvalidTransaction> {
    if gas_used > system.get_gas_limit() { ... }
    else if blob_gas_used > system.get_blob_gas_limit() { ... }
    else if computational_native_used > MAX_NATIVE_COMPUTATIONAL { ... }
    else if pubdata_used > system.get_pubdata_limit() { ... }
    else if logs_used > MAX_NUMBER_OF_LOGS { ... }
    else { Ok(()) }
}
```

When a log is emitted, `tx_number` (u32) is stored in `GenericLogContent`. At serialization time the `From<&LogContent>` impl converts it to `L2ToL1Log`:

```rust
tx_number_in_block: m.tx_number as u16,   // logs_storage.rs:519
```

This is a **silent truncating cast**. For any transaction with index ≥ 65536, the high 16 bits are discarded, producing a `tx_number_in_block` that aliases an earlier transaction's number. The corrupted field is then hashed into the L2→L1 log Merkle tree root and ultimately into the block's public inputs.

### Impact Explanation

- **L2→L1 log misattribution**: logs emitted by transactions ≥ 65536 carry a `tx_number_in_block` that belongs to a different, earlier transaction.
- **Merkle root corruption**: the L2→L1 log tree root (committed on-chain and used by the settlement layer) is computed over the corrupted log encodings, producing an incorrect root.
- **Public-input divergence**: the proving system commits to this incorrect root as part of the public inputs, meaning the proof attests to a state that does not match the actual execution.
- **L2→L1 message proof failure / fund loss**: users who submitted L2→L1 messages in the affected transactions cannot produce valid Merkle proofs against the on-chain root, permanently locking or losing bridged assets.

### Likelihood Explanation

The trigger requires a block containing more than 65535 transactions. With a minimum EVM intrinsic gas cost of 21000 per transaction, this demands a block gas limit of at least ~1.37 billion gas. While current production limits make this impractical, the system imposes **no explicit protocol-level cap on `current_transaction_number`**, and the block gas limit is an operator-controlled parameter read from the oracle. A sequencer configured with a very high gas limit, or a future protocol upgrade that raises the limit, would expose this path to any unprivileged user who can submit transactions. The absence of a guard is the root cause; the gas limit is only an incidental, non-enforced barrier.

### Recommendation

1. Add an explicit check in `check_for_block_limits` (or before incrementing `current_transaction_number`) that rejects any transaction that would push `current_transaction_number` above `u16::MAX`:

```rust
if block_data.current_transaction_number >= u16::MAX as u32 {
    return Err(InvalidTransaction::BlockTransactionLimitReached);
}
```

2. Change the cast in `From<&LogContent> for L2ToL1Log` from a silent truncation to a checked conversion that returns an error or panics on overflow:

```rust
tx_number_in_block: u16::try_from(m.tx_number)
    .expect("tx_number exceeds u16::MAX; block limit should have prevented this"),
```

3. Widen `tx_number_in_block` in `L2ToL1Log` to `u32` if the protocol allows it, and update the on-chain ABI accordingly.

### Proof of Concept

1. Configure a block with `gas_limit` set to a value ≥ 65536 × 21000 (≈ 1.37 billion).
2. Submit 65537 minimal ETH-transfer transactions from funded accounts.
3. The 65537th transaction has `current_transaction_number = 65536`. When it emits an L2→L1 log (e.g., an L1→L2 priority-tx result log), `push_l1_l2_tx_log(65536, ...)` is called.
4. At serialization, `65536u32 as u16 = 0`, so the log's `tx_number_in_block` is `0` — identical to the very first transaction in the block.
5. The L2→L1 Merkle tree root is computed over this corrupted log, producing a root that does not match the true execution order.
6. Any Merkle proof constructed for the 65537th transaction's L2→L1 message will be invalid against the committed root, permanently blocking withdrawal of any funds bridged in that transaction. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** zk_ee/src/common_structs/logs_storage.rs (L44-47)
```rust
    ///
    /// The L2 transaction number in a block, in which the log was sent
    ///
    pub tx_number_in_block: u16,
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L495-524)
```rust
impl<A: Allocator> From<&LogContent<A>> for L2ToL1Log {
    fn from(m: &LogContent<A>) -> Self {
        let (sender, key, value) = match m.data {
            GenericLogContentData::UserMsg(UserMsgData {
                address, data_hash, ..
            }) => (
                // TODO: move into const
                B160::from_limbs([0x8008, 0, 0]),
                address.into(),
                data_hash,
            ),
            GenericLogContentData::L1TxLog(L1TxLog { tx_hash, success }) => {
                let data = if success { U256::from(1) } else { U256::ZERO };
                (
                    // TODO: move into const
                    B160::from_limbs([0x8001, 0, 0]),
                    tx_hash,
                    Bytes32::from_u256_be(&data),
                )
            }
        };
        Self {
            l2_shard_id: 0,
            is_service: true,
            tx_number_in_block: m.tx_number as u16,
            sender,
            key,
            value,
        }
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L139-212)
```rust
                            let next_block_gas_used =
                                block_data.block_gas_used + tx_processing_result.gas_used;
                            let next_block_computational_native_used = block_data
                                .block_computational_native_used
                                + tx_processing_result.computational_native_used;
                            let next_block_pubdata_used =
                                block_data.block_pubdata_used + tx_processing_result.pubdata_used;
                            let block_logs_used = system.io.logs_len();
                            let next_block_blob_gas_used =
                                block_data.block_blob_gas_used + tx_processing_result.blob_gas_used;

                            // Check if the transaction made the block reach any of the limits
                            // for gas, native, pubdata or logs.
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
                            } else {
                                // Now update the accumulators
                                block_data.block_gas_used = next_block_gas_used;
                                block_data.block_computational_native_used =
                                    next_block_computational_native_used;
                                block_data.block_pubdata_used = next_block_pubdata_used;
                                block_data.block_blob_gas_used = next_block_blob_gas_used;

                                if starts_service_block {
                                    is_service_block = true;
                                    can_start_service_block_after_upgrade = false;
                                } else if is_first_tx && tx_processing_result.is_upgrade_tx {
                                    can_start_service_block_after_upgrade = true;
                                } else if can_start_service_block_after_upgrade
                                    && !tx_processing_result.is_service_tx
                                {
                                    can_start_service_block_after_upgrade = false;
                                }

                                is_first_tx = false;

                                // Finish the frame opened before processing the tx
                                system.finish_global_frame(None)?;

                                let (status, output, contract_address) =
                                    match tx_processing_result.result {
                                        ExecutionResult::Success { output } => match output {
                                            ExecutionOutput::Call(output) => (true, output, None),
                                            ExecutionOutput::Create(output, contract_address) => {
                                                (true, output, Some(contract_address))
                                            }
                                        },
                                        ExecutionResult::Revert { output } => (false, output, None),
                                    };

                                block_data
                                    .transaction_hashes_accumulator
                                    .add_tx_hash(&tx_processing_result.tx_hash);
                                if tx_processing_result.is_priority_tx {
                                    block_data
                                        .enforced_transaction_hashes_accumulator
                                        .add_tx_hash(&tx_processing_result.tx_hash);
                                    batch_data.add_tx_hash(&tx_processing_result.tx_hash);
                                }
                                if tx_processing_result.is_upgrade_tx {
                                    block_data
                                        .upgrade_tx_recorder
                                        .add_upgrade_tx_hash(&tx_processing_result.tx_hash);
                                }
                                block_data.current_transaction_number += 1;
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/mod.rs (L44-93)
```rust
fn check_for_block_limits<S: EthereumLikeTypes>(
    system: &mut System<S>,
    gas_used: u64,
    computational_native_used: u64,
    pubdata_used: u64,
    logs_used: u64,
    blob_gas_used: u64,
) -> Result<(), InvalidTransaction>
where
    S::IO: IOSubsystemExt,
    <S as SystemTypes>::Metadata: ZkSpecificPricingMetadata,
{
    if gas_used > system.get_gas_limit() {
        system_log!(
            system,
            "Block gas limit reached, invalidating transaction\n"
        );
        Err(InvalidTransaction::BlockGasLimitReached)
    } else if blob_gas_used > system.get_blob_gas_limit() {
        system_log!(
            system,
            "Block blob gas limit reached, invalidating transaction\n"
        );
        Err(InvalidTransaction::BlockBlobGasLimitReached)
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/block_data.rs (L6-24)
```rust
pub struct ZKBasicBlockDataKeeper<EA: TxHashesAccumulator> {
    /// Current transaction number within the block
    pub current_transaction_number: u32,
    /// Rolling Keccak hash of all transaction hashes in execution order
    pub transaction_hashes_accumulator: TransactionsRollingKeccakHasher,
    /// Accumulator for L1->L2 transaction hashes (enforced transactions)
    /// It's generic as it needs to be different for different post-ops(sequencing, proving aggregation, proving batch, etc).
    pub enforced_transaction_hashes_accumulator: EA,
    /// Records the hash of any upgrade transaction (max one per block)
    pub upgrade_tx_recorder: UpgradeTx,
    /// Total gas consumed by all transactions in the block
    pub block_gas_used: u64,
    /// Total pubdata produced by all transactions
    pub block_pubdata_used: u64,
    /// Total native computational resources used by all transactions
    pub block_computational_native_used: u64,
    /// Amount of blob gas used in the block
    pub block_blob_gas_used: u64,
}
```
