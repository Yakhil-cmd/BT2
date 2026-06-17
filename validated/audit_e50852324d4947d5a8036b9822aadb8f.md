### Title
Silent Discard of `Result` from EIP-7002/7251 Post-Block System Operations Causes Inconsistent State Transition - (`basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs`)

---

### Summary

In `post_tx_op_sequencing.rs`, the return values of `eip6110_events_parser`, `eip7002_system_part`, and `eip7251_system_part` are unconditionally discarded with `let _ = ...`. These functions return `Result<bool, SystemError>` and, for the EIP-7002 and EIP-7251 variants, perform **storage writes** that mutate the withdrawal/consolidation request queue state. If either function fails mid-execution after committing some storage writes (e.g., advancing the queue head pointer) but before completing all writes (e.g., resetting the excess/count), the predeploy contract storage is left in an inconsistent state. The error is silently swallowed, the block is sealed with this corrupted state, and no panic or propagation occurs.

---

### Finding Description

In `post_op` inside `post_tx_op_sequencing.rs`:

```rust
// Environment may have no such contracts predeployed for tests or sequencing purposes
let _ = eip6110_events_parser(&system, &mut requests_hasher);
let _ = eip7002_system_part(&mut system, &mut requests_hasher);
let _ = eip7251_system_part(&mut system, &mut requests_hasher);
``` [1](#0-0) 

All three functions return `Result<bool, SystemError>`. The comment acknowledges the intent to tolerate the "not deployed" case, but `let _ =` discards **all** error variants indiscriminately.

`eip7002_system_part` and `eip7251_system_part` each follow this execution sequence:

1. Check if the predeploy contract is deployed (returns `Err` if not — no side effects).
2. Read queue head/tail from storage.
3. If queue is non-empty, write the EIP-7685 type byte to `requests_hasher`, then read each queue entry and write it to `requests_hasher`.
4. **Write** the new queue head pointer back to storage (or zero it out if the queue is now empty).
5. Call `update_excess_withdrawal_requests_and_reset_count`, which **writes** the new excess value and **resets** the count slot to zero. [2](#0-1) [3](#0-2) 

If step 4 succeeds (queue head advanced) but step 5 fails (excess/count reset fails), the function returns `Err`. Because the caller discards this error with `let _ =`, the block is sealed with:

- The queue head pointer advanced (requests logically dequeued), **but**
- The excess withdrawal request counter not updated, **and**
- The per-block count not reset to zero.

The next block's `eip7002_system_part` will read a stale excess value and a non-zero count, computing an incorrect new excess. This compounds across blocks.

The same structural issue exists in `eip7251_system_part`: [4](#0-3) 

Additionally, if either function fails after writing the EIP-7685 type byte and partial request data to `requests_hasher` (step 3 fails mid-loop), the `requests_hash` computed at the end of `post_op` will be derived from a partially-populated hasher:

```rust
let requests_hash = Bytes32::from_array(requests_hasher.finalize().into());
``` [5](#0-4) 

---

### Impact Explanation

**State-transition bug / storage rollback bug.** The post-block system operations for EIP-7002 and EIP-7251 are not wrapped in a rollback frame. A mid-execution failure leaves the predeploy contract storage in a split state: the queue head has advanced (dequeuing requests) but the excess/count accounting has not been updated. This inconsistency persists into subsequent blocks, causing the excess withdrawal/consolidation request counters to diverge from the correct Ethereum specification values. Over multiple blocks this compounds, producing a state root that diverges from what a correct Ethereum client would compute — a direct state-transition correctness failure.

---

### Likelihood Explanation

The trigger requires that the predeploy contracts are deployed (i.e., a post-Pectra environment) and that a storage write inside `update_excess_withdrawal_requests_and_reset_count` returns an error. While storage write failures are uncommon under normal operation, the code path is reachable whenever the EIP-7002/7251 queue is non-empty. Any internal error in the storage model (e.g., oracle failure in the proving environment, allocation failure, or a defect surfaced by a crafted block) that occurs specifically during the excess/count reset writes — but after the queue head write — will trigger the inconsistency silently. The comment explicitly acknowledges that the error path is expected to be hit in some environments, confirming the code is designed to reach this branch.

---

### Recommendation

Replace the blanket `let _ =` discards with explicit error handling that distinguishes the "not deployed" case (which is intentionally tolerated) from all other errors (which should propagate):

```rust
// eip7002 example
match eip7002_system_part(&mut system, &mut requests_hasher) {
    Ok(_) => {}
    Err(SystemError::LeafDefect(e))
        if e.to_string().contains("not deployed") => {}
    Err(e) => return Err(e.into()),
}
```

Or, better, add an explicit pre-check for contract deployment before calling the function, and propagate all errors from the function body unconditionally.

---

### Proof of Concept

1. Deploy the EIP-7002 withdrawal request predeploy contract at `WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS` with nonce=1 and non-empty bytecode.
2. Submit a transaction that calls the predeploy contract and enqueues at least one withdrawal request (incrementing the queue tail and count slot).
3. Arrange for the storage model to return an `Err` specifically on the write to `WITHDRAWAL_REQUEST_COUNT_STORAGE_SLOT` (the count reset in `update_excess_withdrawal_requests_and_reset_count`) — this can be triggered by a defect in the oracle layer during proving.
4. Observe that `eip7002_system_part` returns `Err` after having successfully written the new queue head pointer.
5. Because `let _ = eip7002_system_part(...)` discards the error, `post_op` continues and calls `result_keeper.record_sealed_block(...)` with no indication of failure.
6. The sealed block's storage state has the queue head advanced but the count slot non-zero and the excess slot stale — diverging from the correct Ethereum post-Pectra state transition. [1](#0-0) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs (L89-93)
```rust
        // Environment may have no such contracts predeployed for tests or sequencing purposes
        let _ = eip6110_events_parser(&system, &mut requests_hasher);
        let _ = eip7002_system_part(&mut system, &mut requests_hasher);
        let _ = eip7251_system_part(&mut system, &mut requests_hasher);

```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs (L94-95)
```rust
        let requests_hash = Bytes32::from_array(requests_hasher.finalize().into());
        system_log!(system, "Requests hash = {:?}\n", &requests_hash);
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7002_withdrawal_contract/mod.rs (L49-76)
```rust
pub fn eip7002_system_part<S: EthereumLikeTypes>(
    system: &mut System<S>,
    requests_hasher: &mut impl crypto::sha256::Digest,
) -> Result<bool, SystemError>
where
    S::IO: IOSubsystemExt,
{
    let mut resources = S::Resources::from_native(
        <S::Resources as Resources>::Native::from_computational(u64::MAX),
    );

    let props = resources.with_infinite_ergs(|resources| {
        system.io.read_account_properties(
            ExecutionEnvironmentType::NoEE,
            resources,
            &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            AccountDataRequest::empty()
                .with_nonce()
                .with_observable_bytecode_len(),
        )
    })?;

    let is_contract = props.nonce.0 == 1 && props.observable_bytecode_len.0 > 0;
    if is_contract == false {
        return Err(SystemError::LeafDefect(internal_error!(
            "EIP-7002 withdrawal contract is not deployed"
        )));
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7002_withdrawal_contract/mod.rs (L169-176)
```rust
    if num_dequeued == 0 {
        // we do not even need to reset the queue pointers as it's a hard invariant
        assert!(queue_head_index.is_zero());
        assert!(queue_tail_index.is_zero());
        update_excess_withdrawal_requests_and_reset_count(system)?;
        return Ok(false);
    }

```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7002_withdrawal_contract/mod.rs (L238-276)
```rust
    let new_queue_head_index = queue_head_index + U256::from(num_dequeued as u64);
    if new_queue_head_index == queue_tail_index {
        logger_log!(logger, "EIP-7002 withdrawal queue is now empty\n");

        resources.with_infinite_ergs(|resources| {
            system.io.storage_write::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
                &WITHDRAWAL_REQUEST_QUEUE_HEAD_STORAGE_SLOT,
                &Bytes32::ZERO,
            )
        })?;

        resources.with_infinite_ergs(|resources| {
            system.io.storage_write::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
                &WITHDRAWAL_REQUEST_QUEUE_TAIL_STORAGE_SLOT,
                &Bytes32::ZERO,
            )
        })?;
    } else {
        let value = Bytes32::from_array(new_queue_head_index.to_be_bytes::<32>());
        resources.with_infinite_ergs(|resources| {
            system.io.storage_write::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
                &WITHDRAWAL_REQUEST_QUEUE_HEAD_STORAGE_SLOT,
                &value,
            )
        })?;
    }

    update_excess_withdrawal_requests_and_reset_count(system)?;

    Ok(true)
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7002_withdrawal_contract/mod.rs (L279-342)
```rust
fn update_excess_withdrawal_requests_and_reset_count<S: EthereumLikeTypes>(
    system: &mut System<S>,
) -> Result<(), SystemError>
where
    S::IO: IOSubsystemExt,
{
    let mut resources = S::Resources::from_native(
        <S::Resources as Resources>::Native::from_computational(u64::MAX),
    );

    let mut previous_excess = resources.with_infinite_ergs(|resources| {
        system.io.storage_read::<false>(
            ExecutionEnvironmentType::NoEE,
            resources,
            &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            &EXCESS_WITHDRAWAL_REQUESTS_STORAGE_SLOT,
        )
    })?;

    if previous_excess == Bytes32::MAX {
        previous_excess = Bytes32::ZERO;
    }

    let count = resources.with_infinite_ergs(|resources| {
        system.io.storage_read::<false>(
            ExecutionEnvironmentType::NoEE,
            resources,
            &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            &WITHDRAWAL_REQUEST_COUNT_STORAGE_SLOT,
        )
    })?;

    let base_count = U256::from_be_bytes(previous_excess.as_u8_array())
        + U256::from_be_bytes(count.as_u8_array());

    let (mut maybe_new_excess, uf) =
        base_count.overflowing_sub(U256::from(TARGET_WITHDRAWAL_REQUESTS_PER_BLOCK as u64));
    if uf {
        maybe_new_excess = U256::ZERO;
    }

    let new_excess = Bytes32::from_array(maybe_new_excess.to_be_bytes::<32>());
    resources.with_infinite_ergs(|resources| {
        system.io.storage_write::<false>(
            ExecutionEnvironmentType::NoEE,
            resources,
            &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            &EXCESS_WITHDRAWAL_REQUESTS_STORAGE_SLOT,
            &new_excess,
        )
    })?;

    // reset count
    resources.with_infinite_ergs(|resources| {
        system.io.storage_write::<false>(
            ExecutionEnvironmentType::NoEE,
            resources,
            &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            &WITHDRAWAL_REQUEST_COUNT_STORAGE_SLOT,
            &Bytes32::ZERO,
        )
    })?;

    Ok(())
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7251_consolidation_contract/mod.rs (L185-221)
```rust
    let new_queue_head_index = queue_head_index + U256::from(num_dequeued as u64);
    if new_queue_head_index == queue_tail_index {
        logger_log!(logger, "EIP-7251 consolidation queue is now empty\n");

        resources.with_infinite_ergs(|resources| {
            system.io.storage_write::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
                &CONSOLIDATION_REQUEST_QUEUE_HEAD_STORAGE_SLOT,
                &Bytes32::ZERO,
            )
        })?;

        resources.with_infinite_ergs(|resources| {
            system.io.storage_write::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
                &CONSOLIDATION_REQUEST_QUEUE_TAIL_STORAGE_SLOT,
                &Bytes32::ZERO,
            )
        })?;
    } else {
        let value = Bytes32::from_array(new_queue_head_index.to_be_bytes::<32>());
        resources.with_infinite_ergs(|resources| {
            system.io.storage_write::<false>(
                ExecutionEnvironmentType::NoEE,
                resources,
                &CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
                &CONSOLIDATION_REQUEST_QUEUE_HEAD_STORAGE_SLOT,
                &value,
            )
        })?;
    }

    update_excess_consolidation_requests_and_reset_count(system)?;
```
