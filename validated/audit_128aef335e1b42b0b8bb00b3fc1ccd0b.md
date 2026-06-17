### Title
Silent `u32`→`u16` Truncation of `tx_number_in_block` in L2→L1 Log Serialization — (File: `zk_ee/src/common_structs/logs_storage.rs`)

---

### Summary

`LogContent::tx_number` is stored as `u32`, but the conversion to `L2ToL1Log` casts it to `u16` without any bounds check. The block-level transaction counter (`current_transaction_number: u32`) has no enforced upper bound at `u16::MAX` (65,535). If a block contains more than 65,535 successful transactions, every subsequent L2→L1 log will carry a silently truncated `tx_number_in_block`, producing incorrect log hashes and an incorrect L2→L1 Merkle tree root committed to L1.

---

### Finding Description

In `From<&LogContent<A>> for L2ToL1Log`, the conversion performs an unchecked narrowing cast:

```rust
// zk_ee/src/common_structs/logs_storage.rs, line 519
tx_number_in_block: m.tx_number as u16,
``` [1](#0-0) 

`GenericLogContent::tx_number` is declared as `u32`:

```rust
pub struct GenericLogContent<IOTypes: SystemIOTypesConfig, A: Allocator = Global> {
    pub tx_number: u32,
    ...
}
``` [2](#0-1) 

While `L2ToL1Log::tx_number_in_block` is `u16`:

```rust
pub tx_number_in_block: u16,
``` [3](#0-2) 

The block-level counter that feeds this field is `current_transaction_number: u32` in `ZKBasicBlockDataKeeper`, which increments unconditionally for every successful transaction:

```rust
block_data.current_transaction_number += 1;
``` [4](#0-3) [5](#0-4) 

The `check_for_block_limits` function enforces caps on gas, native resources, pubdata, and log count (`MAX_NUMBER_OF_LOGS = 16,384`), but imposes **no direct cap on the number of transactions per block**: [6](#0-5) 

There is no assertion or `try_from` guard anywhere between the `u32` counter and the `u16` field in the serialized log.

---

### Impact Explanation

`tx_number_in_block` is bytes 2–3 of the canonical 88-byte L2→L1 log encoding:

```rust
buffer[2..4].copy_from_slice(&self.tx_number_in_block.to_be_bytes());
``` [7](#0-6) 

This encoding is hashed per-log (`L2ToL1Log::hash`) and the hashes become leaves of the 16,384-leaf Merkle tree whose root is committed to L1 as part of the block's public input. [8](#0-7) 

If `current_transaction_number` exceeds 65,535, the cast `N as u16` wraps to `N mod 65536`, causing two distinct transactions to share the same `tx_number_in_block`. This produces:

1. **Colliding log hashes** — two logs from different transactions hash to the same value if all other fields are identical.
2. **Incorrect Merkle tree root** — the root committed to L1 does not faithfully represent the actual transaction ordering.
3. **Broken cross-chain message verification** — users constructing Merkle inclusion proofs for L2→L1 messages will receive proofs that do not match the on-chain root, permanently breaking withdrawal/message verification for those transactions.

This is a **state-transition correctness bug** with a **forward/proving divergence** component: the committed root is computed from corrupted leaf data.

---

### Likelihood Explanation

Likelihood is low but non-zero. The block gas limit is operator-controlled and bounded by `MAX_BLOCK_GAS_LIMIT`: [9](#0-8) 

With a minimum of 21,000 gas per transaction, reaching 65,536 transactions requires a block gas limit of at least ~1.37 billion gas. Current deployments use much lower limits. However, the code itself imposes **no explicit per-block transaction count cap**, leaving the threshold reachable if the operator raises the gas limit or if future protocol changes lower per-transaction gas costs. The analog to the external report is exact: a counter increments without an upper-bound check against the width of the field it is eventually stored in.

---

### Recommendation

Add an explicit bounds check before the cast, or enforce a hard cap on `current_transaction_number` in the transaction loop:

```rust
// Option A: panic/error at serialization time
tx_number_in_block: u16::try_from(m.tx_number)
    .expect("tx_number exceeds u16::MAX; block tx count limit violated"),

// Option B: enforce a MAX_TRANSACTIONS_PER_BLOCK <= u16::MAX constant
// in check_for_block_limits, analogous to MAX_NUMBER_OF_LOGS
```

---

### Proof of Concept

1. Configure a block with gas limit ≥ `65_536 × 21_000 = 1_376_256_000`.
2. Submit 65,536 minimal ETH-transfer transactions (21,000 gas each); `current_transaction_number` reaches 65,536.
3. Submit one additional transaction that calls the L1 Messenger to emit an L2→L1 message. `push_message` stores `tx_number = 65_536u32`.
4. In `From<&LogContent<A>> for L2ToL1Log` at line 519: `65_536u32 as u16 == 0u16`, colliding with the first transaction's `tx_number_in_block = 0`.
5. The resulting log hash and Merkle root are incorrect; the L2→L1 message cannot be correctly verified on L1, and any user relying on that log's Merkle proof is permanently unable to finalize their withdrawal or cross-chain message.

### Citations

**File:** zk_ee/src/common_structs/logs_storage.rs (L47-47)
```rust
    pub tx_number_in_block: u16,
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L72-75)
```rust
pub struct GenericLogContent<IOTypes: SystemIOTypesConfig, A: Allocator = Global> {
    pub tx_number: u32,
    pub data: GenericLogContentData<UsizeAlignedByteBox<A>, Bytes32, IOTypes::Address>,
}
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L311-316)
```rust
    pub fn apply_to_array_vec(&self, array_vec: &mut ArrayVec<Bytes32, 16384>) {
        self.list.iter().for_each(|el| {
            let log: L2ToL1Log = el.into();
            array_vec.push(log.hash())
        });
    }
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L449-458)
```rust
    pub fn encode(&self) -> [u8; L2_TO_L1_LOG_SERIALIZE_SIZE] {
        let mut buffer = [0u8; L2_TO_L1_LOG_SERIALIZE_SIZE];
        buffer[0..1].copy_from_slice(&[self.l2_shard_id]);
        buffer[1..2].copy_from_slice(&[if self.is_service { 1 } else { 0 }]);
        buffer[2..4].copy_from_slice(&self.tx_number_in_block.to_be_bytes());
        buffer[4..24].copy_from_slice(&self.sender.to_be_bytes::<20>());
        buffer[24..56].copy_from_slice(self.key.as_u8_ref());
        buffer[56..88].copy_from_slice(self.value.as_u8_ref());
        buffer
    }
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L516-523)
```rust
        Self {
            l2_shard_id: 0,
            is_service: true,
            tx_number_in_block: m.tx_number as u16,
            sender,
            key,
            value,
        }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L212-212)
```rust
                                block_data.current_transaction_number += 1;
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/block_data.rs (L6-8)
```rust
pub struct ZKBasicBlockDataKeeper<EA: TxHashesAccumulator> {
    /// Current transaction number within the block
    pub current_transaction_number: u32,
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L82-93)
```rust
            let block_gas_limit = system.get_gas_limit();
            // First, check block gas limit can be represented as ergs.
            require!(
                block_gas_limit <= MAX_BLOCK_GAS_LIMIT,
                InvalidTransaction::BlockGasLimitTooHigh,
                system
            )?;
            require!(
                tx_gas_limit <= block_gas_limit,
                InvalidTransaction::CallerGasLimitMoreThanBlock,
                system
            )?;
```
