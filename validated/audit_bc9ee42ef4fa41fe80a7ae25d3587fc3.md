### Title
Unbounded Iteration Over All Block Events in `eip6110_events_parser` Without Native Resource Charging — (`basic_bootloader/src/bootloader/block_flow/ethereum/eip_6110_deposit_events_parser/mod.rs`)

---

### Summary

`eip6110_events_parser` scans every event emitted during the entire block (up to `MAX_NUMBER_OF_LOGS = 16,384`) during block finalization. This work is performed outside any transaction's resource budget, using no native resource accounting. An unprivileged transaction sender can fill a block with events to maximize the uncharged proving cost, creating a resource accounting divergence between what users pay and what the prover must compute.

---

### Finding Description

`eip6110_events_parser` is called unconditionally during block finalization in both the proving path (`post_tx_op_proving.rs`) and the sequencing path (`post_tx_op_sequencing.rs`). It iterates over the full event list of the block to find EIP-6110 deposit events:

```rust
for event in system.io.events_iterator() {
    if event.address != &DEPOSIT_CONTRACT_ADDRESS {
        continue;
    }
    // validate and hash deposit event data
}
``` [1](#0-0) 

The loop has no native resource charge for each iteration. The maximum number of events per block is `MAX_NUMBER_OF_LOGS = 16,384`: [2](#0-1) 

This function is invoked in `post_op_io_touching_impl` (proving path) and directly in `post_op` (sequencing path), both of which execute after all transactions have been processed and outside any per-transaction resource budget: [3](#0-2) [4](#0-3) 

The block log limit is enforced per-transaction during the tx loop via `check_for_block_limits`: [5](#0-4) 

However, the proving cost of iterating all 16,384 events in `eip6110_events_parser` during finalization is never charged to any transaction. Each iteration involves address comparison, topic array access, and (for matching events) SHA-256 hashing of 576 bytes of event data — all real proving work.

By contrast, the EIP-7002 and EIP-7251 system parts are bounded by protocol constants (`MAX_WITHDRAWAL_REQUESTS_PER_BLOCK = 16`, `MAX_CONSOLIDATION_REQUESTS_PER_BLOCK = 2`), making their loop costs negligible: [6](#0-5) [7](#0-6) 

`eip6110_events_parser` has no such protocol-level bound on the number of events it must scan.

---

### Impact Explanation

**Impact: Low–Medium.** The proving cost of iterating up to 16,384 events in `eip6110_events_parser` is not reflected in any transaction's gas or native resource charge. This creates a resource accounting divergence: the operator bears additional proving costs that were not paid for by users. In the worst case (block filled to the log limit), the uncharged proving work for the finalization scan is proportional to 16,384 iterations of address comparison plus SHA-256 hashing for any matching deposit events. This does not cause a block to fail to execute, but it does mean the operator subsidizes proving costs that should be borne by the transactions that emitted the events.

---

### Likelihood Explanation

**Likelihood: High.** Any unprivileged EVM transaction can emit events via `LOG0`–`LOG4` opcodes. The block log limit (`MAX_NUMBER_OF_LOGS = 16,384`) is enforced per-transaction, but the cost of scanning all those events in `eip6110_events_parser` is never charged. A single block filled with many small transactions each emitting one event reaches the maximum scan cost with no additional cost to the attacker beyond normal EVM gas for the `LOG` opcodes themselves.

---

### Recommendation

Charge native resources proportional to the number of events scanned in `eip6110_events_parser`. One approach is to pre-charge a fixed native cost per event scanned before entering the loop, analogous to how `add_interop_root` charges `INTEROP_ROOT_STORAGE_NATIVE_COST + per_root_computational_native_cost()` per root: [8](#0-7) 

Alternatively, account for the scan cost as part of the block-level finalization overhead and ensure it is reflected in the block's native resource budget.

---

### Proof of Concept

1. Deploy a contract that emits a `LOG1` event in a loop (e.g., 100 events per transaction).
2. Fill a block with such transactions until `MAX_NUMBER_OF_LOGS = 16,384` is reached (enforced by `check_for_block_limits`).
3. During `post_op`, `eip6110_events_parser` iterates all 16,384 events. Each iteration performs at minimum an address comparison (`event.address != &DEPOSIT_CONTRACT_ADDRESS`) and a topic length/value check.
4. None of this iteration work is charged as native resource to any transaction — the transactions only paid EVM gas for the `LOG` opcodes themselves.
5. The operator must prove the full 16,384-iteration scan at their own cost, creating a discrepancy between paid-for and actual proving work. [9](#0-8)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_6110_deposit_events_parser/mod.rs (L25-52)
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
}
```

**File:** zk_ee/src/common_structs/logs_storage.rs (L25-25)
```rust
pub const MAX_NUMBER_OF_LOGS: u64 = 16_384;
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

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs (L89-92)
```rust
        // Environment may have no such contracts predeployed for tests or sequencing purposes
        let _ = eip6110_events_parser(&system, &mut requests_hasher);
        let _ = eip7002_system_part(&mut system, &mut requests_hasher);
        let _ = eip7251_system_part(&mut system, &mut requests_hasher);
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/mod.rs (L84-91)
```rust
    } else if !cfg!(feature = "resources_for_tester") && logs_used > MAX_NUMBER_OF_LOGS {
        // ZKsync OS-specific resources are not checked for evm tester
        system_log!(
            system,
            "Block logs limit reached, invalidating transaction\n"
        );
        Err(InvalidTransaction::BlockL2ToL1LogsLimitReached)
    } else {
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7002_withdrawal_contract/mod.rs (L42-42)
```rust
const MAX_WITHDRAWAL_REQUESTS_PER_BLOCK: usize = 16;
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7251_consolidation_contract/mod.rs (L34-34)
```rust
const MAX_CONSOLIDATION_REQUESTS_PER_BLOCK: usize = 2;
```

**File:** basic_system/src/system_implementation/system/io_subsystem.rs (L236-246)
```rust
        // For native we charge for the storage and the computation of the rolling
        // hash (keccak of old hash || new root).
        let native = <Self::Resources as Resources>::Native::from_computational(
            INTEROP_ROOT_STORAGE_NATIVE_COST + per_root_computational_native_cost(),
        );

        let to_charge = Self::Resources::from_native(native);
        resources.charge(&to_charge)?;

        self.interop_root_storage.push_root(interop_root)
    }
```
