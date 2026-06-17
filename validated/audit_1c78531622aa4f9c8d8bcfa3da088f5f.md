### Title
Unbounded Event Scan in `eip6110_events_parser` During Block Finalization Runs Outside Resource Metering — (File: `basic_bootloader/src/bootloader/block_flow/ethereum/eip_6110_deposit_events_parser/mod.rs`)

---

### Summary

`eip6110_events_parser` iterates over **every event emitted in the entire block** during post-transaction finalization. The loop runs with no gas or native-resource charging. An unprivileged transaction sender can fill a block with events from arbitrary addresses, forcing the finalization loop to scan all of them at zero cost to the attacker, inflating the RISC-V proving cycle count beyond what any transaction paid for.

---

### Finding Description

`eip6110_events_parser` is called unconditionally at block finalization in both the sequencing and proving post-tx operations: [1](#0-0) [2](#0-1) 

Inside the function, the loop is:

```rust
for event in system.io.events_iterator() {
    if event.address != &DEPOSIT_CONTRACT_ADDRESS {
        continue;
    }
    ...
}
``` [3](#0-2) 

The iterator returns **all** events accumulated across every transaction in the block — not only deposit-contract events. Events from unrelated addresses are skipped with `continue`, but the loop body still executes for each one. No ergs, no native resource, and no block-level counter is charged for this scan.

The block-level resource checks (`check_for_block_limits`) guard only L2-to-L1 logs (`logs_len`) and gas/native/pubdata per transaction. Regular EVM events (LOG0–LOG4) are stored in `events_storage` and are not subject to a hard block-level count cap enforced in `check_for_block_limits`: [4](#0-3) 

The events themselves are charged gas to the emitting transaction (LOG opcode cost), but the **finalization-time scan cost** is entirely uncharged. The two costs are decoupled.

---

### Impact Explanation

The block finalization phase runs after the transaction loop, outside any per-transaction or per-block native resource budget. The `MAX_NATIVE_COMPUTATIONAL` ceiling is enforced only inside `check_for_block_limits` during the tx loop: [5](#0-4) 

Post-tx operations are not subject to this ceiling. An attacker who fills a block with the maximum gas-affordable number of LOG-emitting transactions forces `eip6110_events_parser` to scan all resulting events at proving time, consuming RISC-V cycles that were never accounted for in any transaction's native resource budget. In the proving path this is called with `expect`, so a cycle-budget overrun that causes the prover to abort would be a hard block-proving failure (DoS on the proving pipeline for that block).

---

### Likelihood Explanation

Any unprivileged EOA can deploy a contract that emits LOG events and call it repeatedly within a block. No special privilege, oracle access, or governance role is required. The attacker pays only the EVM gas cost of the LOG opcodes, not the finalization scan cost. The attack is repeatable every block.

---

### Recommendation

1. Charge a native resource cost proportional to the number of events scanned inside `eip6110_events_parser` (e.g., deduct from a block-level finalization budget).
2. Alternatively, maintain a separate counter for total EVM events per block and enforce a hard cap analogous to `MAX_NUMBER_OF_LOGS`, rejecting transactions that would exceed it before they are committed.
3. Restructure the deposit-event scan to use a pre-filtered index rather than a full linear scan of all block events.

---

### Proof of Concept

1. Attacker deploys contract `Spammer` with a function `spam(uint n)` that executes `emit Noise()` in a loop `n` times.
2. Attacker submits enough transactions calling `spam(k)` to fill the block gas limit with LOG0 opcodes (cheapest event: 375 gas each; at 15 M gas limit ≈ 40,000 events).
3. None of these events originate from `DEPOSIT_CONTRACT_ADDRESS`, so `eip6110_events_parser` skips all of them — but still iterates over all ~40,000 entries.
4. The finalization scan executes ~40,000 iterations with zero native resource charged to any transaction.
5. In the proving run (`post_op_io_touching_impl`), `eip6110_events_parser` is called with `expect`, meaning any prover-side abort propagates as a hard failure, stalling block proof generation. [6](#0-5) [2](#0-1)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs (L90-92)
```rust
        let _ = eip6110_events_parser(&system, &mut requests_hasher);
        let _ = eip7002_system_part(&mut system, &mut requests_hasher);
        let _ = eip7251_system_part(&mut system, &mut requests_hasher);
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_proving.rs (L207-217)
```rust
        if eip6110_events_parser(&*system, &mut intermediate_hasher)
            .expect("must filter EIP-6110 deposit requests")
        {
            let requests_hash = intermediate_hasher.finalize_reset();
            system_log!(
                system,
                "EIP-6110 ops hash = {:?}\n",
                Bytes32::from_array(requests_hash.into())
            );
            requests_hasher.update(requests_hash);
        }
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_6110_deposit_events_parser/mod.rs (L25-51)
```rust
pub fn eip6110_events_parser<S: EthereumLikeTypes>(
    system: &System<S>,
    requests_hasher: &mut impl crypto::sha256::Digest,
) -> Result<bool, SystemError>
where
    S::IO: IOSubsystemExt + IOTeardown<S::IOTypes>,
{
    // we can not easily get the number from one scan, so we will accumulate into hasher directly

    let mut event_encountered = false;
    let mut logger = system.get_logger();
    for event in system.io.events_iterator() {
        if event.address != &DEPOSIT_CONTRACT_ADDRESS {
            continue;
        }
        if event.topics.len() > 0 && event.topics[0] == DEPOSIT_EVENT_SIGNATURE_HASH {
            if event_encountered == false {
                event_encountered = true;
                requests_hasher.update(&[DEPOSIT_REQUEST_EIP_7685_TYPE]);
            }
            let Ok(_) = validate_and_write_event_data(event, requests_hasher, &mut logger) else {
                panic!("invalid deposit event structure");
            };
        }
    }

    Ok(event_encountered)
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/mod.rs (L44-94)
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
}
```

**File:** zk_ee/src/system/constants.rs (L26-26)
```rust
pub const MAX_NATIVE_COMPUTATIONAL: u64 = 1 << 35;
```
