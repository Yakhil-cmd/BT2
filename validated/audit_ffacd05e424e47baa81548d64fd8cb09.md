### Title
Silent Discard of `Result` from EIP-7002/7251/6110 Request Processors Produces Incorrect `requests_hash` — (`File: basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs`)

---

### Summary

In `post_tx_op_sequencing.rs`, the return values of `eip6110_events_parser`, `eip7002_system_part`, and `eip7251_system_part` are all explicitly discarded with `let _ =`. Each function returns `Result<bool, SystemError>`. If any of them fails mid-execution — after having already written bytes into `requests_hasher` but before completing all storage queue-pointer updates — the error is silently swallowed, the hasher is left in a partially-updated state, and the `requests_hash` committed into the sealed block header is incorrect.

---

### Finding Description

In `post_tx_op_sequencing.rs` lines 89–94:

```rust
// Environment may have no such contracts predeployed for tests or sequencing purposes
let _ = eip6110_events_parser(&system, &mut requests_hasher);
let _ = eip7002_system_part(&mut system, &mut requests_hasher);
let _ = eip7251_system_part(&mut system, &mut requests_hasher);

let requests_hash = Bytes32::from_array(requests_hasher.finalize().into());
``` [1](#0-0) 

The justification comment covers only the "contract not deployed" case. However, `eip7002_system_part` and `eip7251_system_part` can also return `Err` for storage I/O failures, propagated via `?` throughout their bodies.

Inside `eip7002_system_part`, the execution order is:

1. Read queue head/tail from storage (lines 142–158) — `?` propagated.
2. **Write the EIP-7685 type byte into `requests_hasher`** (line 177) — this is a side-effect on the shared hasher.
3. Loop over up to 16 requests, reading 3 storage slots each and calling `requests_hasher.update(...)` (lines 181–236) — `?` propagated on every read.
4. Write the new queue-head pointer back to storage (lines 238–272) — `?` propagated.
5. Call `update_excess_withdrawal_requests_and_reset_count` (line 274) — `?` propagated. [2](#0-1) 

If a storage read inside the loop (step 3) returns `Err`, the function returns early. At that point `requests_hasher` already contains the type byte (step 2) and partial request data (step 3), but the queue-head pointer has **not** been advanced (step 4 never ran). The `let _ =` in the caller discards the `Err`, and `requests_hasher.finalize()` is called on the partially-written state.

The identical pattern exists in `eip7251_system_part`. [3](#0-2) 

---

### Impact Explanation

The `requests_hash` is embedded in the sealed block header via `result_keeper.record_sealed_block(metadata.block_level.header)`. [4](#0-3) 

An incorrect `requests_hash` causes:

1. **State-transition divergence**: The block header committed by ZKsync OS contains a `requests_hash` that does not match what Ethereum consensus computes from the same on-chain events and storage state. The block is invalid from the consensus layer's perspective.
2. **Storage inconsistency / double-processing**: Because the queue-head pointer was never advanced, the same withdrawal/consolidation requests will be re-read and re-hashed in the next block, compounding the divergence.
3. **Unprovability**: A prover that re-executes the block will compute a different `requests_hash` than the one committed, making the block unprovable or causing a proof-verification failure.

---

### Likelihood Explanation

The EIP-7002 and EIP-7251 contracts are deployed in any production Pectra-fork environment. Any storage I/O error inside the loop — which can be triggered by an attacker who queues withdrawal or consolidation requests (the contracts are publicly callable) and then causes the storage subsystem to encounter an edge-case error — will silently corrupt the `requests_hash`. Even without a deliberate attacker, a transient internal error in the storage layer is sufficient. The broad `let _ =` suppresses all error variants, not just "contract not deployed."

---

### Recommendation

Replace the blanket `let _ =` discards with targeted error handling that only ignores the specific "contract not deployed" variant and propagates all other errors:

```rust
match eip7002_system_part(&mut system, &mut requests_hasher) {
    Ok(_) => {}
    Err(SystemError::LeafDefect(e)) if e.is_not_deployed() => {}
    Err(e) => return Err(e.into()),
}
```

Alternatively, separate the "not deployed" check from the processing logic so that the hasher is only touched after confirming the contract is present and all storage operations succeed atomically.

---

### Proof of Concept

1. Deploy the EIP-7002 withdrawal contract at `WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS`.
2. Call the contract from an EOA to enqueue ≥1 withdrawal request (publicly callable).
3. Arrange for the storage read of the second request's slot (inside the loop at line ~196) to return `Err` (e.g., by exhausting a resource limit or triggering a storage-model edge case).
4. `eip7002_system_part` returns `Err` after having written the type byte `0x01` and the first request's data into `requests_hasher`.
5. `let _ =` discards the error.
6. `requests_hasher.finalize()` produces a hash that includes partial withdrawal data.
7. `result_keeper.record_sealed_block(...)` commits this incorrect `requests_hash` into the block header.
8. The queue-head pointer remains at its old value; the next block re-processes the same requests, further corrupting subsequent `requests_hash` values. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs (L86-95)
```rust
        use crypto::sha256::Digest;
        let mut requests_hasher = crypto::sha256::Sha256::new();

        // Environment may have no such contracts predeployed for tests or sequencing purposes
        let _ = eip6110_events_parser(&system, &mut requests_hasher);
        let _ = eip7002_system_part(&mut system, &mut requests_hasher);
        let _ = eip7251_system_part(&mut system, &mut requests_hasher);

        let requests_hash = Bytes32::from_array(requests_hasher.finalize().into());
        system_log!(system, "Requests hash = {:?}\n", &requests_hash);
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs (L105-105)
```rust
        result_keeper.record_sealed_block(metadata.block_level.header);
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7002_withdrawal_contract/mod.rs (L49-52)
```rust
pub fn eip7002_system_part<S: EthereumLikeTypes>(
    system: &mut System<S>,
    requests_hasher: &mut impl crypto::sha256::Digest,
) -> Result<bool, SystemError>
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7002_withdrawal_contract/mod.rs (L177-236)
```rust
    requests_hasher.update([WITHDRAWAL_REQUEST_EIP_7685_TYPE]);

    let mut logger = system.get_logger();

    for i in 0..num_dequeued {
        let queue_storage_slot = WITHDRAWAL_REQUEST_QUEUE_STORAGE_OFFSET
            + ((queue_head_index + U256::from(i as u64)) * SLOTS_PER_REQUEST);
        let slot_0 = Bytes32::from_array(queue_storage_slot.to_be_bytes::<32>());
        let slot_1 = Bytes32::from_array((queue_storage_slot + U256::from(1)).to_be_bytes::<32>());
        let slot_2 = Bytes32::from_array((queue_storage_slot + U256::from(2)).to_be_bytes::<32>());

        let slot_0 = resources.with_infinite_ergs(|resources| {
            system.io.storage_read::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
                &slot_0,
            )
        })?;
        let slot_1 = resources.with_infinite_ergs(|resources| {
            system.io.storage_read::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
                &slot_1,
            )
        })?;
        let slot_2 = resources.with_infinite_ergs(|resources| {
            system.io.storage_read::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
                &slot_2,
            )
        })?;

        logger_log!(logger, "Processing EIP-7002 withdrawal queue element with:");

        logger_log!(logger, "\nAddress = ");
        let address = &slot_0.as_u8_array_ref()[12..];
        let _ = logger.log_data(address.iter().copied());
        requests_hasher.update(address);

        let pubkey_part_0 = slot_1.as_u8_array_ref();
        let pubkey_part_1 = &slot_2.as_u8_array_ref()[..16];

        requests_hasher.update(pubkey_part_0);
        requests_hasher.update(pubkey_part_1);
        logger_log!(logger, "\nPubkey = ");
        let _ = logger.log_data(ExactSizeChain::new(
            pubkey_part_0.iter().copied(),
            pubkey_part_1.iter().copied(),
        ));

        // NOTE: we need to bytereverse it
        let amount = &slot_2.as_u8_array_ref()[16..][..8];
        let amount = u64::from_be_bytes(amount.try_into().unwrap());
        logger_log!(logger, "\nAmount = {amount}\n");
        requests_hasher.update(amount.to_le_bytes());
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7251_consolidation_contract/mod.rs (L105-183)
```rust
    requests_hasher.update([CONSOLIDATION_REQUEST_EIP_7685_TYPE]);

    let mut logger = system.get_logger();

    for i in 0..num_dequeued {
        let queue_storage_slot = CONSOLIDATION_REQUEST_QUEUE_STORAGE_OFFSET
            + ((queue_head_index + U256::from(i as u64)) * SLOTS_PER_REQUEST);
        let slot_0 = Bytes32::from_array(queue_storage_slot.to_be_bytes::<32>());
        let slot_1 = Bytes32::from_array((queue_storage_slot + U256::from(1)).to_be_bytes::<32>());
        let slot_2 = Bytes32::from_array((queue_storage_slot + U256::from(2)).to_be_bytes::<32>());
        let slot_3 = Bytes32::from_array((queue_storage_slot + U256::from(3)).to_be_bytes::<32>());

        let slot_0 = resources.with_infinite_ergs(|resources| {
            system.io.storage_read::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
                &slot_0,
            )
        })?;
        let slot_1 = resources.with_infinite_ergs(|resources| {
            system.io.storage_read::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
                &slot_1,
            )
        })?;
        let slot_2 = resources.with_infinite_ergs(|resources| {
            system.io.storage_read::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
                &slot_2,
            )
        })?;
        let slot_3 = resources.with_infinite_ergs(|resources| {
            system.io.storage_read::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
                &slot_3,
            )
        })?;

        logger_log!(
            logger,
            "Processing EIP-7251 consolidation queue element with:"
        );

        logger_log!(logger, "\nAddress = ");
        let address = &slot_0.as_u8_array_ref()[12..];
        let _ = logger.log_data(address.iter().copied());
        requests_hasher.update(address);

        let source_pubkey_part_0 = slot_1.as_u8_array_ref();
        let source_pubkey_part_1 = &slot_2.as_u8_array_ref()[..16];

        requests_hasher.update(source_pubkey_part_0);
        requests_hasher.update(source_pubkey_part_1);
        logger_log!(logger, "\nSource pubkey = ");
        let _ = logger.log_data(ExactSizeChain::new(
            source_pubkey_part_0.iter().copied(),
            source_pubkey_part_1.iter().copied(),
        ));

        let target_pubkey_part_0 = &slot_2.as_u8_array_ref()[16..];
        let target_pubkey_part_1 = slot_3.as_u8_array_ref();

        requests_hasher.update(target_pubkey_part_0);
        requests_hasher.update(target_pubkey_part_1);
        logger_log!(logger, "\nTarget pubkey = ");
        let _ = logger.log_data(ExactSizeChain::new(
            target_pubkey_part_0.iter().copied(),
            target_pubkey_part_1.iter().copied(),
        ));

        logger_log!(logger, "\n");
    }
```
