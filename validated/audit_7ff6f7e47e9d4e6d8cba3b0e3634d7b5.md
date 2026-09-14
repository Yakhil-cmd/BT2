### Title
Uncontrolled resource consumption via un-released per-slot entry-bytes budget reservation on PoH recording failure - (File: `runtime/src/bank/entry_bytes_budget.rs`)

### Summary
`EntryBytesBudget` tracks the number of serialized entry bytes consumed for a slot by only ever incrementing an atomic counter via `reserve()`; there is no corresponding decrement/release method in the type at all. [1](#0-0)  In `Consumer::execute_and_commit_transactions_locked`, the budget is reserved for the serialized size of the transactions that were about to be recorded into a PoH entry, *before* the recording attempt actually succeeds. [2](#0-1)  When the subsequent `record_transactions` call fails (e.g. `PohRecorderError::MaxHeightReached`), the code explicitly rolls back the cost-tracker accounting via `remove_added_transaction_costs`, but never rolls back the `entry_bytes_budget` reservation that was just taken. [3](#0-2)  This is directly analogous to the Tomcat HTTP/2 "backlog tracking" leak: a per-unit accounting counter is incremented when a unit of work starts, and when that unit of work is aborted/reset before completion, the counter is never decremented, permanently consuming capacity from a bounded resource.

### Finding Description
`EntryBytesBudget::reserve` is a monotonically-increasing, best-effort admission-control counter meant to bound total serialized entry bytes recorded per slot (`slot_limit`):
```
pub fn reserve(&self, bytes: u64) -> std::result::Result<(), EntryBytesReserveError> {
    loop {
        let current = self.consumed.load(Ordering::Acquire);
        let next = current.saturating_add(bytes);
        if next > self.slot_limit { return Err(...); }
        if self.consumed.compare_exchange(current, next, ...).is_ok() { return Ok(()); }
    }
}
``` [4](#0-3) 

There is no `release`, `unreserve`, or `sub` method anywhere on this type, so once bytes are reserved for a batch of transactions, that portion of the slot's byte budget is permanently consumed for the remaining lifetime of that bank/slot — regardless of whether the reserved bytes were ever actually recorded into a PoH entry.

In the banking-stage commit path, the reservation happens speculatively before the recording attempt:
```
let reserved_bytes = bank.entry_bytes_budget().reserve(entry_bytes)...;
let (record_transactions_summary, record_us) = measure_us!(reserved_bytes.map(|_| {
    self.transaction_recorder.record_transactions(bank.bank_id(), processed_transactions)
}));
``` [5](#0-4) 

If `record_transactions` subsequently fails (e.g. the PoH recorder has already advanced past the max tick height for the slot, returning `PohRecorderError::MaxHeightReached`), the function unwinds the *cost tracker* changes but leaves the entry-bytes reservation intact:
```
if let Err(recorder_err) = recording_result {
    Self::remove_added_transaction_costs(bank, &transaction_costs);
    ...
    return ExecuteAndCommitTransactionsOutput { ...,
        commit_transactions_result: Err(recorder_err), ... };
}
``` [3](#0-2) 

Because a leader continually races multiple concurrently-processed transaction batches against the PoH tick clock near the end of a slot, `record_transactions` failing with `MaxHeightReached` for late-arriving batches is an expected, frequently-hit condition — not an edge case. Each such failure permanently "burns" `entry_bytes` worth of the slot's budget without ever having recorded a single byte into the actual block. An adversary who can get transactions processed by banking stage close to the end of a slot (trivially achievable by any unprivileged sender flooding valid transactions near tick-height boundaries) can repeatedly trigger this failure path, exhausting the slot's `entry_bytes_budget` early. Once exhausted, all subsequent legitimate transaction batches for that slot are rejected at `reserve()` with `ExceedsSlotLimit`, mapped to `PohRecorderError::MaxHeightReached`, causing the leader to stop packing any further transactions into the remainder of the slot even though the actual PoH entry bytes recorded are far below the real limit.

### Impact Explanation
This degrades leader block production: a bounded per-slot resource (`entry_bytes_budget`) can be exhausted by transaction batches that never actually get recorded, causing the leader to prematurely refuse to record further legitimate transactions for the remainder of the slot. This is a transaction-triggered leader-side resource-exhaustion/DoS affecting block production capacity, directly analogous to the reported Tomcat allocation-leak-on-reset class of bug (resource accounting incremented on start-of-work but never decremented on abort).

### Likelihood Explanation
`PohRecorderError::MaxHeightReached` on the recording path is a routine, easily and repeatedly triggerable condition during normal end-of-slot contention — no special privileges or malformed input are required, only submitting ordinary transactions that get bucketed into batches processed near the slot's max tick height. This makes the leak straightforward to trigger repeatedly by an unprivileged sender across many slots.

### Recommendation
Add a `release`/`unreserve` method to `EntryBytesBudget` that decrements `consumed` by the previously reserved amount, and call it in `Consumer::execute_and_commit_transactions_locked` whenever `record_transactions` fails after a successful `reserve()` call, mirroring the existing `remove_added_transaction_costs` rollback for the cost tracker.

### Proof of Concept
1. As leader, allow banking stage to process a batch of transactions late in a slot, close to `max_tick_height`.
2. `execute_and_commit_transactions_locked` computes `entry_bytes` for the batch and successfully calls `bank.entry_bytes_budget().reserve(entry_bytes)`, consuming that much of the slot budget.
3. `self.transaction_recorder.record_transactions(...)` fails with `PohRecorderError::MaxHeightReached` because the PoH tick clock has advanced past the slot's max height in the interim.
4. The code path at lines 397–414 removes the added transaction costs from the cost tracker but does not call any release on `entry_bytes_budget`; the reserved bytes remain permanently counted in `consumed`.
5. Repeating this near the end of many slots (trivial for any unprivileged sender submitting a steady stream of transactions) steadily narrows/exhausts the effective `entry_bytes_budget` available for legitimately recorded entries, causing the leader to reject transaction recording (`ExceedsSlotLimit` → `MaxHeightReached`) well before the slot's real byte budget is consumed by actually-recorded entries.

### Citations

**File:** runtime/src/bank/entry_bytes_budget.rs (L8-43)
```rust
#[derive(Debug)]
pub struct EntryBytesBudget {
    consumed: AtomicU64,
    slot_limit: u64,
}

impl EntryBytesBudget {
    pub const fn new(slot_limit: u64) -> Self {
        Self {
            consumed: AtomicU64::new(0),
            slot_limit,
        }
    }

    pub const fn slot_limit(&self) -> u64 {
        self.slot_limit
    }

    pub fn reserve(&self, bytes: u64) -> std::result::Result<(), EntryBytesReserveError> {
        loop {
            let current = self.consumed.load(Ordering::Acquire);
            let next = current.saturating_add(bytes);
            if next > self.slot_limit {
                return Err(EntryBytesReserveError::ExceedsSlotLimit);
            }

            if self
                .consumed
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }
}
```

**File:** core/src/banking_stage/consumer.rs (L355-381)
```rust
        let mut entry_bytes = SERIALIZED_ENTRIES_OVERHEAD;
        let (processed_transactions, processing_results_to_transactions_us) = measure_us!({
            let mut processed_transactions =
                Vec::with_capacity(processed_counts.processed_transactions_count as usize);
            for (processing_result, tx) in processing_results
                .iter()
                .zip(batch.sanitized_transactions())
            {
                if processing_result.was_processed() {
                    entry_bytes += tx.serialized_size() as u64;
                    processed_transactions.push(tx.to_versioned_transaction());
                }
            }
            processed_transactions
        });

        let reserved_bytes =
            bank.entry_bytes_budget()
                .reserve(entry_bytes)
                .map_err(|err| match err {
                    EntryBytesReserveError::ExceedsSlotLimit => PohRecorderError::MaxHeightReached,
                });
        let (record_transactions_summary, record_us) = measure_us!(reserved_bytes.map(|_| {
            self.transaction_recorder
                .record_transactions(bank.bank_id(), processed_transactions)
        }));
        execute_and_commit_timings.record_us = record_us;
```

**File:** core/src/banking_stage/consumer.rs (L397-414)
```rust
        if let Err(recorder_err) = recording_result {
            Self::remove_added_transaction_costs(bank, &transaction_costs);

            Self::extend_processed_retryable_transaction_indexes(
                &mut retryable_transaction_indexes,
                &processing_results,
            );

            return ExecuteAndCommitTransactionsOutput {
                cost_model_throttled_transactions_count,
                cost_model_us,
                transaction_counts,
                retryable_transaction_indexes,
                commit_transactions_result: Err(recorder_err),
                execute_and_commit_timings,
                error_counters,
            };
        }
```
