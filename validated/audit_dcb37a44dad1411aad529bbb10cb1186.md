### Title
Memory Leak in `ExternalWorker::check_batch` on `AllocationFailure` Leaks Shared-Memory Transaction Batch and Response Regions - ([File: core/src/banking_stage/consume_worker.rs])

### Summary
This is analyzed under `cfg(unix)` `external` scheduler module, which processes `PackToWorkerMessage` batches coming from an external scheduler process over a shared-memory `rts_alloc::Allocator`. `check_batch` allocates a response region up front, then calls `check_resolve_pubkeys`, which itself allocates a per-transaction pubkeys region inside a loop. If any of these allocations fails (`ExternalConsumeWorkerError::AllocationFailure`), the error is propagated with `?` all the way out of `check_batch` without ever sending a `WorkerToPackMessage` response and without ever freeing the allocations already made in this call.

### Finding Description
`check_batch` first allocates a response region via `allocate_check_response_region`: [1](#0-0) 

It then conditionally calls `check_resolve_pubkeys`, propagating any error with `?`: [2](#0-1) 

Inside `check_resolve_pubkeys`, for every transaction with address-lookup-table–resolved keys, a fresh allocation is made from the shared allocator and written into the per-transaction response slot: [3](#0-2) 

If this `self.allocator.allocate(...)` call returns `None` (allocator exhausted / fragmented), the function returns `Err(ExternalConsumeWorkerError::AllocationFailure)`: [4](#0-3) 

That error propagates through the `?` in `check_batch` at line 534, terminating `check_batch` immediately. At that point:
1. The `responses_ptr`/`responses` region allocated at lines 496-501 is dropped without ever being freed or transmitted back to the client for it to free.
2. Any `pubkeys_allocation` regions successfully allocated for *earlier* transactions in the same `check_resolve_pubkeys` loop (before the failing one) are also dropped and never referenced again, since the `CheckResponse` slots holding their offsets are never sent to the client.
3. The `message.batch` shared-memory region itself (owned by the external scheduler client) is never returned via a `WorkerToPackMessage`, so the client can never learn to free it, and the worker itself never frees it either — it becomes permanently unrecoverable in the shared allocator (`rts_alloc::Allocator`) for the remaining lifetime of that allocator/session.

This mirrors the CVE-2020-26420 bug class exactly: a parser/handler that allocates memory while processing untrusted input and fails to release it on certain error paths, allowing repeated crafted input to exhaust memory over time.

The `rts_alloc::Allocator` is a fixed-size shared-memory region (`allocator_size` configured at session setup, e.g. `64 * 1024 * 1024` in tests, see `ExternalTestFrame` setup) shared between the leader-side scheduler client and the worker process — it is not general heap memory, so leaked allocations directly and permanently reduce this small, fixed-capacity pool. [5](#0-4) 

### Impact Explanation
This is a leader-side DoS/reliability bug: repeated transactions that trigger address-table-resolution allocation failures during `check_batch` (any transaction using ALTs, submitted while the allocator is near capacity, or via crafted concurrent load driving the allocator toward exhaustion) permanently consume shared-memory allocator space. Since the allocator backing the TPU-to-pack / pack-to-worker / worker-to-pack pipeline is fixed-size, sustained leakage will eventually starve the allocator, causing subsequent `allocate()` calls throughout the pipeline (`tpu_to_pack.rs`, `check_batch`, `execute_batch`, response building) to fail, degrading or halting the leader's transaction-processing pipeline for the affected worker/session. This is a transaction-triggered availability impact confined to the external-scheduler binary/session as described, without affecting bank state, funds, or consensus directly.

### Likelihood Explanation
Triggering requires the shared allocator to already be near its capacity limit (allocator exhaustion is a prerequisite for the leak-inducing `AllocationFailure` branch to fire), which under sustained load or adversarial packet flooding is plausible but not trivially reachable with a single transaction under normal operating conditions. The bug is a genuine missing-cleanup defect on an error path reachable purely from transaction content (a transaction using address lookup tables), but requires allocator pressure to manifest.

### Recommendation
On any early-return error path within `check_batch` (specifically the `?` after `check_resolve_pubkeys`, and any other early return after the initial response-region allocation), free the already-allocated `responses_ptr`/`responses` region and any partially-allocated `pubkeys_allocation` regions from prior loop iterations before returning. Alternatively, restructure `check_resolve_pubkeys` to accumulate resolved-pubkey allocations into a rollback list so that an allocation failure mid-loop triggers automatic freeing of all previously succeeded allocations in that call, and ensure `check_batch` always attempts to send back (or otherwise dispose of) `message.batch` even on internal `AllocationFailure`, so the shared allocator region owned by the external client is never left dangling.

### Proof of Concept
Conceptual trigger sequence (cannot be fully executed without the external-scheduler test harness, but derivable from `core/src/banking_stage/consume_worker.rs` test module referenced at lines 1295-1382):
1. Configure a `ClientSession`/`SchedulerBindingsBridge` with a small `allocator_size` (as in `setup_external_test_frame_disable_features`, e.g. reduce from `64 * 1024 * 1024` to a small value).
2. Submit a stream of check-batch (`LOAD_ADDRESS_LOOKUP_TABLES` flag set) `PackToWorkerMessage`s each containing at least one transaction using address lookup tables (so `check_resolve_pubkeys` performs allocations at line 715-719).
3. Continue submitting until the shared allocator approaches exhaustion so that `self.allocator.allocate(...)` at line 715-719 returns `None` for some transaction in the batch.
4. Observe that `check_batch` returns `Err(AllocationFailure)`, no `WorkerToPackMessage` is emitted for that batch, and the memory for `message.batch`, the `responses_ptr` region, and any prior-loop `pubkeys_allocation`s in that batch are never freed — verify via allocator instrumentation (e.g., `allocator.clean_remote_free_lists()` / free-space counters) that available allocator capacity permanently decreases after each such failed batch, independent of subsequent `drop_transaction`/`handle_worker_response` calls on the client side.

### Citations

**File:** core/src/banking_stage/consume_worker.rs (L496-501)
```rust
            // Allocate space for all responses.
            let (responses_ptr, responses) = allocate_check_response_region(
                &self.allocator,
                usize::from(message.batch.num_transactions),
            )
            .ok_or(ExternalConsumeWorkerError::AllocationFailure)?;
```

**File:** core/src/banking_stage/consume_worker.rs (L526-535)
```rust
            if message.flags & check_flags::LOAD_ADDRESS_LOOKUP_TABLES != 0 {
                self.check_resolve_pubkeys(
                    &parsing_results,
                    &parsing_and_resolve_results,
                    &txs,
                    &max_ages,
                    response_slice,
                    root_bank.slot(),
                )?;
            }
```

**File:** core/src/banking_stage/consume_worker.rs (L711-726)
```rust
                let (sharable_keys, alt_invalidation_slot) = if account_keys.len()
                    > num_static_account_keys
                {
                    let num_pubkeys = account_keys.len().wrapping_sub(num_static_account_keys);
                    let pubkeys_allocation = self
                        .allocator
                        .allocate(num_pubkeys.wrapping_mul(core::mem::size_of::<Pubkey>()) as u32)
                        .ok_or(ExternalConsumeWorkerError::AllocationFailure)?
                        .cast();
                    // SAFETY: non-overlapping and appropriately sized.
                    unsafe {
                        Self::copy_loaded_addresses(
                            account_keys.iter().skip(num_static_account_keys),
                            pubkeys_allocation,
                        )
                    };
```

**File:** core/src/banking_stage/consume_worker.rs (L1333-1342)
```rust
            let logon = ClientLogon {
                worker_count: 1,
                allocator_size: 64 * 1024 * 1024,
                allocator_handles: 1,
                tpu_to_pack_capacity: 16,
                progress_tracker_capacity: 16,
                pack_to_worker_capacity: 16,
                worker_to_pack_capacity: 16,
                flags: 0,
            };
```
