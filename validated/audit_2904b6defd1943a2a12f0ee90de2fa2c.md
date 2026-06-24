Audit Report

## Title
Unbounded Stable-Memory Scan in `get_neuron_ids_ready_to_finalize` Can Exhaust Instruction Limit and Permanently Stall Maturity-Disbursement Timer — (`rs/nns/governance/src/maturity_disbursement_index.rs`)

## Summary
`MaturityDisbursementIndex::get_neuron_ids_ready_to_finalize` performs an unbounded `range(..=max_key).collect()` over a `StableBTreeMap`, materialising every overdue entry into a heap `BTreeSet` in a single synchronous call. This is invoked on every tick of `FinalizeMaturityDisbursementsTask`. If the index grows large enough, the scan exhausts the per-message instruction limit, the timer callback traps without returning, and the `RecurringAsyncTask` framework never reschedules the task, permanently stalling all maturity-disbursement finalisation until a canister upgrade.

## Finding Description

**Unbounded scan (root cause):**
`get_neuron_ids_ready_to_finalize` issues `range(..=max_key).collect()` with no upper bound on the number of entries returned. [1](#0-0) 

An O(1) alternative, `get_next_entry()`, already exists in the same file but is not used in the hot path. [2](#0-1) 

**Call chain:**
`next_maturity_disbursement_to_finalize` calls `get_neuron_ids_ready_to_finalize_maturity_disbursement`, collects the full result set, then iterates to find the first non-locked neuron — forcing a full scan even though only one entry is needed. [3](#0-2) 

**Timer scheduling:**
`FinalizeMaturityDisbursementsTask` is scheduled unconditionally at canister startup and calls `finalize_maturity_disbursement` → `try_finalize_maturity_disbursement` → `next_maturity_disbursement_to_finalize` on every invocation. [4](#0-3) [5](#0-4) 

**No rescheduling on trap:**
`finalize_maturity_disbursement` only returns a retry delay on a clean `Err`; if the execution traps (instruction limit exceeded), `execute()` never returns and `RecurringAsyncTask` never reschedules the timer. [6](#0-5) 

**Entry accumulation:**
Any neuron controller can call `disburse_maturity` up to `MAX_NUM_DISBURSEMENTS = 10` times per neuron, each inserting one `(timestamp, neuron_id)` entry into the stable BTreeMap. Entries are only removed upon successful finalisation. [7](#0-6) [8](#0-7) 

**Instruction limit:**
The per-message instruction limit is 40 B instructions (the code comment in `disburse_maturity.rs` references 50 B for the NNS subnet with DTS, but the hard ceiling is confirmed in `subnet_config.rs`). [9](#0-8) [10](#0-9) 

## Impact Explanation
If the instruction limit is exceeded, the timer callback traps, the task is never rescheduled, and all pending maturity disbursements across all NNS neurons are frozen: no ICP is minted, no disbursement record is popped, and the maturity-disbursement subsystem is effectively DoS'd until a canister upgrade is deployed. This matches the allowed impact class: **Application/platform-level DoS of an NNS subsystem with concrete user harm** (High, $2,000–$10,000), though the substantial preconditions (see Likelihood) place it at the lower end of that range or Medium.

## Likelihood Explanation
Triggering the bug requires accumulating enough overdue index entries to exhaust ~40–50 B instructions in a single scan. At a conservative ~10,000 instructions per stable-BTreeMap node traversal, this requires on the order of 4–5 million overdue entries simultaneously (≈ 400,000–500,000 neurons each with 10 pending disbursements). The NNS has ~500,000 neurons, so the theoretical ceiling is reachable, but:

- **Deliberate attack:** An adversary must control or coordinate hundreds of thousands of neurons that have each earned enough maturity to initiate 10 disbursements. The economic cost is prohibitive today.
- **Organic growth:** As `disburse_maturity` adoption grows and reward events accumulate, the index will grow organically. A large-scale simultaneous accumulation (e.g., after a period of high reward distribution with delayed finalisation) could approach the threshold without deliberate attack, but this remains a low-probability scenario in the near term.

Likelihood is **low**, with a realistic long-term operational risk as NNS adoption grows.

## Recommendation
Replace the full `collect()` scan with an incremental approach:

1. Use the already-implemented `get_next_entry()` to fetch the minimum-timestamp entry in O(1).
2. If that neuron is locked, iterate forward one entry at a time using `range((Excluded(current_key), Unbounded)).next()` until a non-locked neuron is found or a soft instruction-count budget is reached.
3. Alternatively, add a `get_first_n_ready(n, now)` method returning at most `n` entries (e.g., `n = 100`), bounding scan cost per timer invocation — consistent with how `unstake_maturity_of_dissolved_neurons` already applies a `max_num_neurons` bound. [11](#0-10) 

## Proof of Concept
A deterministic integration test or PocketIC test can reproduce the stall:

1. Create N neurons (e.g., N = 50,000 for a conservative test) each with 10 pending maturity disbursements whose `finalize_disbursement_timestamp_seconds` is in the past.
2. Advance the simulated clock past all finalization timestamps.
3. Trigger `FinalizeMaturityDisbursementsTask::execute()`.
4. Observe that `get_neuron_ids_ready_to_finalize` scans all 10×N entries; measure instruction consumption via `ic_cdk::api::performance_counter` or the PocketIC instruction counter.
5. At sufficiently large N, confirm the task traps with `InstructionLimitExceeded` and the timer is not rescheduled.

A unit-level benchmark using the existing `canbench-rs` infrastructure (already present in `neuron_store.rs`) can measure the per-entry instruction cost and extrapolate the threshold N without requiring a full replica. [1](#0-0)

### Citations

**File:** rs/nns/governance/src/maturity_disbursement_index.rs (L82-91)
```rust
    pub fn get_neuron_ids_ready_to_finalize(
        &self,
        now_seconds: TimestampSeconds,
    ) -> BTreeSet<NeuronId> {
        let max_key = (now_seconds, u64::MAX);
        self.finalization_timestamp_neuron_id_to_null
            .range(..=max_key)
            .map(|((_, neuron_id), _)| neuron_id)
            .collect()
    }
```

**File:** rs/nns/governance/src/maturity_disbursement_index.rs (L93-100)
```rust
    /// Returns the next entry of the index.
    pub fn get_next_entry(&self) -> Option<(TimestampSeconds, NeuronIdProto)> {
        self.finalization_timestamp_neuron_id_to_null
            .first_key_value()
            .map(|((finalization_timestamp, neuron_id), _)| {
                (finalization_timestamp, NeuronIdProto::from_u64(neuron_id))
            })
    }
```

**File:** rs/nns/governance/src/governance/disburse_maturity.rs (L38-40)
```rust
/// The maximum number of disbursements in a neuron. This makes it possible to do daily
/// disbursements after every reward event (as 10 > 7).
const MAX_NUM_DISBURSEMENTS: usize = 10;
```

**File:** rs/nns/governance/src/governance/disburse_maturity.rs (L46-52)
```rust
// We do not retry the task more frequently than once a minute, so that if there is anything wrong
// with the task, we don't use too many resources. How this is chosen: assuming the task can max out
// the 50B instruction limit and it takes 2B instructions per DTS slice, then the task can run for
// 25 rounds; with 1.5 rounds per second, it will take ~ 16 seconds to run. The minimum task
// interval is chosen to be larger than 16 seconds so that the canister would be able to do other
// work in the meantime.
const RETRY_INTERVAL: Duration = Duration::from_secs(60);
```

**File:** rs/nns/governance/src/governance/disburse_maturity.rs (L306-319)
```rust
    if num_disbursements >= MAX_NUM_DISBURSEMENTS {
        return Err(InitiateMaturityDisbursementError::TooManyDisbursements);
    }

    let disbursement_in_progress = MaturityDisbursement {
        destination: Some(destination),
        amount_e8s: disbursement_maturity_e8s,
        timestamp_of_disbursement_seconds,
        finalize_disbursement_timestamp_seconds,
    };

    neuron_store
        .with_neuron_mut(id, |neuron| {
            neuron.add_maturity_disbursement_in_progress(disbursement_in_progress);
```

**File:** rs/nns/governance/src/governance/disburse_maturity.rs (L462-469)
```rust
    let Some(neuron_id) = neuron_store
        .get_neuron_ids_ready_to_finalize_maturity_disbursement(now_seconds)
        .into_iter()
        .find(|neuron_id| !in_flight_commands.contains_key(&neuron_id.id))
    else {
        // If all neurons are locked, we don't need to finalize anything.
        return Ok(None);
    };
```

**File:** rs/nns/governance/src/governance/disburse_maturity.rs (L544-554)
```rust
pub async fn finalize_maturity_disbursement(
    governance: &'static LocalKey<RefCell<Governance>>,
) -> Duration {
    match try_finalize_maturity_disbursement(governance).await {
        Ok(_) => governance.with_borrow(get_delay_until_next_finalization),
        Err(err) => {
            println!("FinalizeMaturityDisbursementTask failed: {}", err);
            RETRY_INTERVAL
        }
    }
}
```

**File:** rs/nns/governance/src/timer_tasks/mod.rs (L42-43)
```rust
    FinalizeMaturityDisbursementsTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    UnstakeMaturityOfDissolvedNeuronsTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
```

**File:** rs/nns/governance/src/timer_tasks/finalize_maturity_disbursements.rs (L20-33)
```rust
#[async_trait]
impl RecurringAsyncTask for FinalizeMaturityDisbursementsTask {
    async fn execute(self) -> (Duration, Self) {
        let delay = finalize_maturity_disbursement(self.governance).await;
        (delay, self)
    }

    fn initial_delay(&self) -> Duration {
        self.governance
            .with_borrow(get_delay_until_next_finalization)
    }

    const NAME: &'static str = "finalize_maturity_disbursements";
}
```

**File:** rs/config/src/subnet_config.rs (L36-36)
```rust
pub(crate) const MAX_INSTRUCTIONS_PER_MESSAGE: NumInstructions = NumInstructions::new(40 * B);
```

**File:** rs/nns/governance/src/neuron_store.rs (L630-636)
```rust
    /// When a neuron is finally dissolved, if there is any staked maturity it is moved to regular maturity
    /// which can be spawned (and is modulated).
    pub fn unstake_maturity_of_dissolved_neurons(
        &mut self,
        now_seconds: u64,
        max_num_neurons: usize,
    ) {
```
