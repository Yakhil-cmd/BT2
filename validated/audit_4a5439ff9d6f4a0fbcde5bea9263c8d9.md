### Title
Unbounded shared-allocator memory leak on `AllocationFailure` in `ExternalCheckWorker::check_batch` leading to check-worker crash/DoS - (File: `core/src/banking_stage/transaction_scheduler/check_worker.rs`)

### Summary
`ExternalCheckWorker::check_batch` allocates a `CheckResponse` region from the shared `rts_alloc::Allocator` before running downstream checks, but if a later step in the same call (`check_resolve_pubkeys`, when resolving address-lookup-table accounts) fails to allocate and returns `Err`, that error is propagated with `?` without ever freeing the already-allocated response region. Every failed batch permanently consumes shared-allocator memory, and once the allocator is exhausted the check-worker thread itself terminates (its `run()` loop propagates the error), producing an availability impact analogous to the WildFly report's leaked reconnect-loop resources.

### Finding Description
In `check_batch`, the response region is allocated first: [1](#0-0) 

Processing then proceeds through several optional checks driven by message flags, including `check_resolve_pubkeys` when `LOAD_ADDRESS_LOOKUP_TABLES` is set: [2](#0-1) 

`check_resolve_pubkeys` itself performs a per-transaction allocation to store resolved account keys, and returns `ExternalCheckWorkerError::AllocationFailure` if that allocation fails: [3](#0-2) 

When this `?` fires (line 331 in `check_batch`), the function returns immediately. The `responses_ptr`/`CheckResponseRegion` allocated at line 285-289 - and any pubkey allocations already made for earlier transactions in the same batch inside the `check_resolve_pubkeys` loop - are never freed; there is no `CheckResponsesPtr::free` or `allocator.free` call anywhere on this error path. Compare this to the success path, where the caller (`ExternalCheckWorker`/scheduler) is expected to free the region only after receiving it via `CheckWorkerToPackMessage`, and to explicit test helpers that always pair `allocate_batch`/`free_batch` and `check_responses`/`free`: [4](#0-3) [5](#0-4) 

The allocator backing this is a fixed-size shared-memory region (`allocator_size` set at session setup, e.g. 64MB in tests), shared between the leader process and the external scheduler process: [6](#0-5) 

Once such a leaked allocation accumulates enough to exhaust the shared pool, any subsequent `allocate_check_response_region` or `check_resolve_pubkeys` allocation attempt will also fail, and the error propagates all the way through `process_message` → `iterate` → `run`, which simply returns the `Err` and exits the loop, terminating the check-worker thread rather than recovering: [7](#0-6) 

### Impact Explanation
This is a resource-consumption / availability bug (CWE-400/401), analogous to the WildFly finding (unclosed connections accumulating in a retry loop causing OOM). Here, failed allocations in the check-worker's account-resolution path leak fixed shared-memory allocator capacity instead of freeing it. Because the shared allocator is a bounded resource dedicated to the leader's external-scheduler check-worker fleet, repeated leaks can exhaust it, after which (a) further check-worker allocations fail deterministically, and (b) the affected check-worker thread's `run()` loop returns an error and the thread dies, degrading or halting the leader's transaction-checking pipeline. This does not directly move funds or corrupt consensus state, but it is a validator/leader-side denial-of-service condition reachable purely by transaction submission.

### Likelihood Explanation
An unprivileged transaction sender controls whether a transaction uses address lookup tables and how many non-static account keys it references (up to the account limit per transaction), which directly drives the size and number of allocations performed inside `check_resolve_pubkeys`. By submitting a sustained volume of transactions that reference address-lookup-table accounts, an attacker can apply allocation pressure on the shared check-worker allocator, increasing the probability of hitting `AllocationFailure` and thus repeatedly leaking response-region allocations, without requiring any special privileges, leader status, or malicious peers.

### Recommendation
On any error path out of `check_batch` after the response region (and any partial pubkey allocations) has been allocated, explicitly free those allocations before returning the error, e.g. wrap the allocation in a guard/drop type that frees on early return, or restructure `check_batch` to defer freeing to a `finally`-style cleanup that runs for both success and error paths. Additionally, consider making `check_resolve_pubkeys`'s partial allocations (for transactions already processed in the loop before the failing one) get freed on its own error path, rather than leaking them upward.

### Proof of Concept
1. Configure/observe a leader session with a bounded shared allocator size (as in `setup_check_worker_test_frame`, `allocator_size: 64 * 1024 * 1024`).
2. Repeatedly submit transactions that (a) reference address lookup tables with the maximum number of resolvable accounts, and (b) are sent in high volume/concurrency so that many `PackToCheckWorkerMessage` batches are in flight with `LOAD_ADDRESS_LOOKUP_TABLES` set.
3. As the shared allocator nears capacity, some `check_resolve_pubkeys` calls at [8](#0-7)  will hit `AllocationFailure`, causing `check_batch` to return early at line 331 without freeing the `responses_ptr` region allocated at lines 285-289.
4. Continued submission accumulates leaked allocations until the allocator is fully exhausted, after which the check-worker thread's `run()` returns `Err` and terminates, per [9](#0-8) , degrading the leader's transaction-checking capacity.

### Citations

**File:** core/src/banking_stage/transaction_scheduler/check_worker.rs (L229-250)
```rust
        pub fn run(mut self) -> Result<(), ExternalCheckWorkerError> {
            while !self.exit.load(Ordering::Relaxed) {
                self.iterate(Self::RECEIVE_TIMEOUT)?;
            }

            Ok(())
        }

        pub(crate) fn iterate(
            &mut self,
            timeout: Duration,
        ) -> Result<IterationResult, ExternalCheckWorkerError> {
            self.allocator.clean_remote_frees();

            match self.receiver.read_timeout(timeout) {
                Ok(message) => {
                    self.process_message(&message)?;
                    Ok(IterationResult::ProcessedMessage)
                }
                Err(shaq::error::WaitError::Timeout) => Ok(IterationResult::Idle),
            }
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

**File:** core/src/banking_stage/transaction_scheduler/check_worker.rs (L343-352)
```rust
            self.sender
                .try_write(CheckWorkerToPackMessage {
                    batch: message.batch,
                    processed_code: processed_codes::PROCESSED,
                    responses,
                })
                .map_err(|_| ExternalCheckWorkerError::SenderDisconnected)?;

            Ok(())
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

**File:** core/src/banking_stage/transaction_scheduler/check_worker.rs (L982-994)
```rust
            let logon = ClientLogon {
                worker_count: 1,
                check_worker_count: 1,
                allocator_size: 64 * 1024 * 1024,
                allocator_handles: 1,
                tpu_to_pack_capacity: 16,
                progress_tracker_capacity: 16,
                pack_to_worker_capacity: 16,
                worker_to_pack_capacity: 16,
                flags: 0,
                pack_to_check_worker_capacity: 16,
                check_worker_to_pack_capacity: 16,
            };
```

**File:** scheduling-utils/src/responses_region.rs (L142-150)
```rust
    /// Free the batch's allocation.
    ///
    /// # Safety
    ///
    /// - `Self` must be exclusively owned.
    pub unsafe fn free(self, allocator: &Allocator) {
        unsafe { allocator.free(self.ptr.cast()) }
    }
}
```
