### Title
Silent truncation of core assignments beyond 27 tasks drops paid-for coretime without refund - ([File: system-parachains/coretime/coretime-kusama/src/coretime.rs])

### Summary
`CoretimeAllocator::assign_core` truncates any `assignment` vector longer than 28 entries down to the first 27 non-`Idle` entries plus a single injected `Idle` entry absorbing all remaining `PartsOf57600`, before forwarding the (mutated) assignment to the Relay Chain via XCM `Transact`. Any `(CoreAssignment::Task, parts)` entries beyond the 27th are dropped entirely and their `PartsOf57600` are silently reassigned to `Idle`, with no compensating event, refund, or error surfaced to the caller. [1](#0-0) 

### Finding Description
`assign_core` is the `CoretimeInterface` implementation invoked by `pallet_broker`'s internal core-scheduling logic (triggered each timeslice rotation from the workplan built up via `Broker::purchase`, `Broker::renew`, `Broker::assign`, `Broker::partition`, and `Broker::interlace`) to actually communicate the final task-to-core mapping to the Relay Chain. [2](#0-1) 

When the number of distinct assignment entries for a single core exceeds 28, the code:
1. Filters out all pre-existing `Idle` entries and takes only the first 27 non-`Idle` entries via `.filter(...).take(27)`.
2. Sums the `parts` of only those first 27 entries into `total_parts`.
3. Injects a single new `Idle` entry at index 0 whose `parts` = `57_600 - total_parts`, absorbing whatever was truncated away. [3](#0-2) 

Any `(CoreAssignment::Task(id), parts)` entries at position 28+ in the input vector (which correspond to real, previously-purchased/interlaced task allocations from `pallet_broker`'s workplan) are completely discarded, and their `parts` become unassigned/idle time on the Relay Chain rather than being routed to the task that paid for them. There is no error return, no event emission indicating a drop occurred, and no accounting adjustment inside `pallet_broker` reflecting that the task's on-chain workplan entry will not actually be honored on the Relay Chain for that rotation. The `CHANGELOG.md` confirms this exact code was added as "mitigate behaviour with many assignments on one core" (PR polkadot-fellows/runtimes#434), i.e., it was a deliberate stopgap for a Relay Chain limitation rather than a robust fix — the underlying loss of assignments when the limit is exceeded is retained.

### Impact Explanation
If a user's interlacing/partitioning of a single core over its purchased period accumulates more than 27 distinct non-idle task assignments (e.g., through repeated `interlace`/`partition`/`assign` operations building up many small task slices on the same core for the same timeslice window), the assignments beyond the 27th are never transmitted to the Relay Chain — that portion of coretime is effectively wasted as `Idle`. The paying task/tenant receives no compute time for the parts they purchased, with no refund, credit, or on-chain record of the loss.

### Likelihood Explanation
Reaching 28+ simultaneous non-idle assignments on one core requires a user (or set of users coordinating on the same core) to perform enough `interlace`/`assign`/`renew` operations to build up that many distinct task slices before the workplan for that core is next rotated to the Relay Chain. This is governed by `pallet_broker`'s own bounds on interlacing/partitioning (external crate, not fully indexed in this repository), so the precise number of extrinsic calls needed and whether `pallet_broker` itself caps the number of schedule items per core below 28 could not be fully verified from this codebase alone. Based on the code present here, no such cap exists in the `coretime-kusama` runtime configuration itself (`MaxLeasedCores`, `MaxReservedCores`, `MaxAutoRenewals` bound different things, not per-core task counts), so the precondition appears reachable through legitimate, permissionless purchase/interlace flows, though verifying the exact extrinsic sequence requires deeper knowledge of `pallet_broker` internals than is available in this index. [4](#0-3) 

### Recommendation
Do not silently drop excess assignments. Options include: (a) reject/queue the assignment update and emit an event/error when `assignment.len() > 28` so the runtime (or governance) can react instead of silently losing entitlements, (b) track dropped `PartsOf57600` per task in on-chain storage and issue a compensating credit/refund via `pallet_broker`'s revenue/credit mechanism, or (c) enforce a hard cap on the number of simultaneous non-idle assignments per core inside `pallet_broker`'s `interlace`/`assign` extrinsics so this state can never be reached in the first place, rather than handling it reactively and lossily in `CoretimeAllocator::assign_core`.

### Proof of Concept
Rust unit test plan (in `system-parachains/coretime/coretime-kusama` test module):
```rust
#[test]
fn assign_core_does_not_silently_drop_assignments_over_27_tasks() {
    // Build 30 distinct non-idle (CoreAssignment::Task(id), parts) entries
    // summing to 57_600 parts.
    let mut assignment: Vec<(CoreAssignment, PartsOf57600)> = (0..30)
        .map(|i| (CoreAssignment::Task(i), 57_600 / 30))
        .collect();

    // Capture the XCM message that would be sent (mock PolkadotXcm::send_xcm)
    // and decode the `AssignCore` payload.
    CoretimeAllocator::assign_core(0, 100, assignment.clone(), None);

    let sent = decode_last_assign_core_call();
    let (sent_assignment, _end_hint) = (sent.2, sent.3);

    // Assertion: total non-idle parts sent must equal total non-idle parts requested.
    let requested_task_parts: u32 = assignment.iter()
        .filter(|(a, _)| *a != CoreAssignment::Idle)
        .map(|(_, p)| *p as u32).sum();
    let sent_task_parts: u32 = sent_assignment.iter()
        .filter(|(a, _)| *a != CoreAssignment::Idle)
        .map(|(_, p)| *p as u32).sum();

    assert_eq!(
        requested_task_parts, sent_task_parts,
        "task parts were silently dropped during truncation without refund/event"
    );
    // Also assert every distinct Task id in the input appears in the output.
    for (a, _) in assignment.iter().filter(|(a, _)| *a != CoreAssignment::Idle) {
        assert!(sent_assignment.iter().any(|(sa, _)| sa == a),
            "task {:?} was dropped from core assignment with no compensation", a);
    }
}
```
Expected current result: the test fails — only 27 of the 30 tasks appear in `sent_assignment`, and `sent_task_parts < requested_task_parts`, confirming silent loss of paid-for coretime with no event or refund emitted.

### Citations

**File:** system-parachains/coretime/coretime-kusama/src/coretime.rs (L203-238)
```rust
	fn assign_core(
		core: CoreIndex,
		begin: RCBlockNumberOf<Self>,
		assignment: Vec<(CoreAssignment, PartsOf57600)>,
		end_hint: Option<RCBlockNumberOf<Self>>,
	) {
		use crate::coretime::CoretimeProviderCalls::AssignCore;

		// The relay chain currently only allows `assign_core` to be called with a complete mask
		// and only ever with increasing `begin`. The assignments must be truncated to avoid
		// dropping that core's assignment completely.

		// This shadowing of `assignment` is temporary and can be removed when the relay can accept
		// multiple messages to assign a single core.
		let assignment = if assignment.len() > 28 {
			let mut total_parts = 0u16;
			// Account for missing parts with a new `Idle` assignment at the start as
			// `assign_core` on the relay assumes this is sorted. We'll add the rest of the
			// assignments and sum the parts in one pass, so this is just initialized to 0.
			let mut assignment_truncated = vec![(CoreAssignment::Idle, 0)];
			// Truncate to first 27 non-idle assignments.
			assignment_truncated.extend(
				assignment
					.into_iter()
					.filter(|(a, _)| *a != CoreAssignment::Idle)
					.take(27)
					.inspect(|(_, parts)| total_parts += *parts)
					.collect::<Vec<_>>(),
			);

			// Set the parts of the `Idle` assignment we injected at the start of the vec above.
			assignment_truncated[0].1 = 57_600u16.saturating_sub(total_parts);
			assignment_truncated
		} else {
			assignment
		};
```

**File:** system-parachains/coretime/coretime-kusama/src/coretime.rs (L311-327)
```rust
impl pallet_broker::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type OnRevenue = BurnCoretimeRevenue;
	type TimeslicePeriod = ConstU32<{ coretime::TIMESLICE_PERIOD }>;
	type MaxLeasedCores = ConstU32<50>;
	type MaxReservedCores = ConstU32<50>;
	type Coretime = CoretimeAllocator;
	type ConvertBalance = sp_runtime::traits::Identity;
	type WeightInfo = weights::pallet_broker::WeightInfo<Runtime>;
	type PalletId = BrokerPalletId;
	type AdminOrigin = EnsureRoot<AccountId>;
	type SovereignAccountOf = SovereignAccountOf;
	type MaxAutoRenewals = ConstU32<100>;
	type PriceAdapter = pallet_broker::MinimumPrice<Balance, MinimumEndPrice>;
	type MinimumCreditPurchase = MinimumCreditPurchase;
}
```
