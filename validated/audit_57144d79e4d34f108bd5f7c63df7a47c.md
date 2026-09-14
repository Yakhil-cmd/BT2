### Title
Unfreed shared-allocator response allocation leaks memory and can terminate a check-worker thread on ALT-resolution failure - (File: core/src/banking_stage/transaction_scheduler/check_worker.rs)

### Summary
`ExternalCheckWorker::check_batch` allocates a `CheckResponse` region from the shared bump allocator before doing per-transaction work, but the early-return error path (`?`) taken when address-lookup-table pubkey resolution fails does not free that allocation, analogous to the ImageMagick `ReadPSDChannel` pattern (CVE-2017-9440) where an allocated buffer is leaked on an error/early-return path during untrusted-input parsing.

### Finding Description
`check_batch` allocates a response region up front: [1](#0-0) 

It then proceeds through several stages, including `check_resolve_pubkeys`, guarded with the `?` operator: [2](#0-1) 

Inside `check_resolve_pubkeys`, additional allocations for resolved ALT pubkeys are made per-transaction, and the function itself can return `Err(ExternalCheckWorkerError::AllocationFailure)` if the allocator is exhausted: [3](#0-2) 

If this call returns `Err`, `check_batch` propagates the error immediately via `?` at line 331, **without ever freeing `responses_ptr`/`responses`** (there is no `CheckResponsesPtr::free` call on the error path) and without freeing any partial pubkey allocations already made for earlier transactions in the same loop. The only place a `CheckResponsesPtr`/`ExecutionResponsesPtr` is freed is in the success path via the `sender.try_write(...)` message, and in `consume_worker.rs`'s `execution_responses`, which explicitly calls `.free(&self.allocator)`: [4](#0-3) 

There is no equivalent free call on the `check_batch` error path.

Additionally, the error propagates further up through `process_message` → `iterate` → `run`: [5](#0-4) 

Since `run` uses `?` inside its polling loop, any `AllocationFailure` terminates the entire check-worker thread, abandoning any allocator state (including the leaked allocation) with it.

### Impact Explanation
Each triggered failure leaks a `CheckResponse` region (and any partially-completed pubkey allocations) from the shared `rts_alloc::Allocator`, which is a fixed-size shared memory region used across all check-worker/consume-worker messages. Repeated leaks degrade available allocator capacity over time, and — more severely — each occurrence also kills the check-worker thread outright (`run()` returns `Err` and exits its polling loop), reducing the number of active check workers. If enough workers are killed this can stall banking-stage transaction checking, which is a validator-availability concern reachable purely from crafted transaction traffic (transactions with address-table lookups), not requiring privileged access.

### Likelihood Explanation
Reaching the `AllocationFailure` branch requires the shared allocator to already be near capacity (e.g., under sustained transaction load with many outstanding batches/ALT resolutions), so a *single* transaction alone is unlikely to trigger it deterministically. This makes the bug primarily a resource-exhaustion/leak issue that accumulates under load rather than an instantly-triggerable single-transaction exploit — it is a genuine unfreed-allocation bug matching the CVE's bug class, but its cluster-impact severity depends on sustained conditions rather than one crafted transaction.

### Recommendation
On every error path out of `check_batch` (and within `check_resolve_pubkeys`'s own error return), explicitly free the already-allocated `responses_ptr`/`CheckResponsesPtr` region and any partial `pubkeys_allocation`s made so far, e.g. via `CheckResponsesPtr::free`/`allocator.free`, before returning `Err`. Consider also making `run()` resilient to a single `AllocationFailure` (e.g., drop and retry the message, or send an error response) instead of terminating the worker thread.

### Proof of Concept
Not concretely reproducible from a single transaction without control over shared-allocator occupancy; the leak and thread-termination are triggered when `self.allocator.allocate(...)` inside `check_resolve_pubkeys` returns `None` (allocator exhausted) while processing a transaction that has address-table lookups (`account_keys().len() > static_account_keys().len()`), which can be driven toward by high-volume ALT-lookup transaction traffic against the check-worker pipeline.

### Citations

**File:** core/src/banking_stage/transaction_scheduler/check_worker.rs (L229-235)
```rust
        pub fn run(mut self) -> Result<(), ExternalCheckWorkerError> {
            while !self.exit.load(Ordering::Relaxed) {
                self.iterate(Self::RECEIVE_TIMEOUT)?;
            }

            Ok(())
        }
```

**File:** core/src/banking_stage/transaction_scheduler/check_worker.rs (L285-289)
```rust
            let (responses_ptr, responses) = allocate_check_response_region(
                &self.allocator,
                usize::from(message.batch.num_transactions),
            )
            .ok_or(ExternalCheckWorkerError::AllocationFailure)?;
```

**File:** core/src/banking_stage/transaction_scheduler/check_worker.rs (L323-332)
```rust
            if message.flags & check_message_flags::LOAD_ADDRESS_LOOKUP_TABLES != 0 {
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

**File:** core/src/banking_stage/transaction_scheduler/check_worker.rs (L400-408)
```rust
                let (sharable_keys, alt_invalidation_slot) = if account_keys.len()
                    > num_static_account_keys
                {
                    let num_pubkeys = account_keys.len().wrapping_sub(num_static_account_keys);
                    let pubkeys_allocation = self
                        .allocator
                        .allocate(num_pubkeys.wrapping_mul(core::mem::size_of::<Pubkey>()) as u32)
                        .ok_or(ExternalCheckWorkerError::AllocationFailure)?
                        .cast();
```

**File:** core/src/banking_stage/consume_worker.rs (L768-778)
```rust
                unsafe {
                    // SAFETY: `region` was produced by this worker using the same shared
                    // allocator and contains `ExecutionResponse` values.
                    let responses = ExecutionResponsesPtr::from_transaction_response_region(
                        region,
                        &self.allocator,
                    );
                    let decoded = responses.iter().copied().collect();
                    responses.free(&self.allocator);
                    decoded
                }
```
