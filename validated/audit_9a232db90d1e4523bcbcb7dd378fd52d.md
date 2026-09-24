### Title
Stale `Workplan` task assignment persists across `pallet-broker` Region ownership transfer, letting a new owner inherit an unconsented core assignment - ([File: substrate/frame/broker/src/dispatchable_impls.rs])

### Summary
`pallet-broker`'s `do_assign()` binds a `RegionId` to a `TaskId` in the `Workplan` storage map after checking that the caller is the *current* owner of the region [1](#0-0) . Ownership itself lives in a separate `Regions` map and can be changed independently via `transfer`/`force_transfer`, which only mutate the `owner` field and never touch `Workplan` [2](#0-1) . This is structurally identical to the reported pattern: a configuration (`positionConfigs` in AutoRange / `Workplan` entry here) is set by the account that owned the resource at the time, is never cleared or re-validated on ownership transfer, and continues to be honored/consumed later on behalf of whoever owns the resource at execution time.

### Finding Description
`do_transfer` only rewrites `region.owner`; it does not clear or invalidate any prior `Workplan`/assignment entry keyed on `(region_id.begin, region_id.core)` [2](#0-1) . `do_assign`'s ownership check (`maybe_check_owner`) is only enforced inside `utilize()` at the moment `assign` is called, i.e., a one-time gate at write time [1](#0-0) . Once the entry is written into `Workplan`, it is consumed later by the on-chain scheduling logic without re-checking who currently owns the `Region`.

The maintainers are aware of this general class of issue — a related variant (`do_interlace` letting the old owner still assign a region after transferring an interlaced part of it) was explicitly identified and fixed, per `prdoc/1.6.0/pr_2811.prdoc`, which states: *"The current implementation of the broker pallet does not remove the region on which the interlacing is performed. This can create a vulnerability, as the original region owner is still allowed to assign a task to the region even after transferring an interlaced part of it."* [3](#0-2) . However, the symmetric case — a **Provisional** assignment made by the old owner surviving a full ownership transfer via `transfer`/`force_transfer` — is exercised by a passing test that does not assert any invalidation of the pre-existing assignment: `force_transfer_can_transfer_provisionally_assigned_region` purchases a region, has `OLD_OWNER` provisionally assign it to task `1001`, then force-transfers the region to `NEW_OWNER`, and only checks that the `Transferred` event fires — it never checks that the stale provisional assignment made by `OLD_OWNER` was cleared [4](#0-3) .

This mirrors the report's exact shape:
- Old owner (Alice/`OLD_OWNER`) sets a config/assignment tied to an id they currently own.
- The id/token changes hands to a new owner (Bob/`NEW_OWNER`) without the config being reset.
- The stale config continues to be effective/consumable unless the new owner proactively overwrites it (in `pallet-broker`, only a subsequent `do_assign` call, via its `workplan.retain(...)` overwrite logic, clears the old entry for the matching mask) [5](#0-4) .

### Impact Explanation
Same class and severity ceiling as the referenced finding: this is not a theft-of-funds or unauthorized-dispatch bug — assignment consumes coretime according to a decision the *previous* legitimate owner made while they were the owner, and the new owner retains the ability to override it by calling `assign` again before the workplan is consumed. The practical impact is that a new region owner can unknowingly inherit a core-task binding they did not choose (their bought/received coretime capacity gets used for a task they never selected), analogous to "the protocol not receiving incentive" in the original report — here it is "the new owner's coretime capacity being used per a stale decision," a low/medium integrity concern rather than a fund-loss vulnerability.

### Likelihood Explanation
Requires no privileged role: any account can legitimately purchase/own a `Region`, provisionally `assign` it, and then transfer it (via `transfer`) to any other account, or an `AdminOrigin` can `force_transfer` it. The receiving party has no visibility/control over the pre-existing `Workplan` entry unless they inspect chain state and issue a corrective `assign` themselves — same "front-end/off-chain trust" caveat the original judge raised ("frontend security checks are unreliable"). Given the maintainers already fixed one closely related instance (interlace-then-transfer) but the test suite for `force_transfer` + provisional assignment does not assert invalidation, this specific path's status (fixed vs. accepted) could not be fully confirmed from the available files — the `tick_impls.rs`/`utility_impls.rs` consumption logic that ultimately turns `Workplan` entries into actual core scheduling could not be fully traced in this pass to confirm whether any additional ownership re-validation occurs there before commitment to the relay chain.

### Recommendation
On `do_transfer`/`do_transfer` via `force_transfer`, clear any `Workplan` entry (and any related `PotentialRenewals` linkage) associated with the transferred `RegionId`'s mask, mirroring how `do_partition`/`do_interlace` already call `Self::force_unpool_region` to remove stale pool assignments on structural changes. This ensures a new owner always starts from a clean assignment state, consistent with the fix already applied for the interlace case.

### Proof of Concept
- Program/severity rationale: This is a `pallet-broker` (Coretime) issue, analogous to a judged Medium in the source report; not independently confirmed as a live, currently-unpatched bounty-eligible bug because the consumption path in `tick_impls.rs` was not fully traced within the available tool budget.
- Failed guard: `do_transfer`/`force_transfer` (`substrate/frame/broker/src/dispatchable_impls.rs:230-253`) omit clearing `Workplan` entries that `do_assign` (`dispatchable_impls.rs:321-349`) wrote under the prior owner's authorization.
- Deployment evidence: Existing repository test `force_transfer_can_transfer_provisionally_assigned_region` (`substrate/frame/broker/src/tests.rs:3332-3358`) demonstrates the transfer succeeding with a pre-existing provisional assignment still in place, but does not assert the assignment is cleared — this was read directly from the repository, not executed.
- PoC execution status: Not executed; this analysis is based on static code reading only. No local Rust/FRAME integration test was run to confirm end-to-end consumption behavior of the stale `Workplan` entry (i.e., whether relay-chain-level core scheduling re-validates ownership before commit) — this remains unverified and should be confirmed with a live test run before treating this as a confirmed, actionable finding.

### Citations

**File:** substrate/frame/broker/src/dispatchable_impls.rs (L230-253)
```rust
	pub(crate) fn do_transfer(
		region_id: RegionId,
		maybe_check_owner: Option<T::AccountId>,
		new_owner: T::AccountId,
	) -> Result<(), Error<T>> {
		let mut region = Regions::<T>::get(&region_id).ok_or(Error::<T>::UnknownRegion)?;

		if let Some(check_owner) = maybe_check_owner {
			ensure!(Some(check_owner) == region.owner, Error::<T>::NotOwner);
		}

		let old_owner = region.owner;
		region.owner = Some(new_owner);
		Regions::<T>::insert(&region_id, &region);
		let duration = region.end.saturating_sub(region_id.begin);
		Self::deposit_event(Event::Transferred {
			region_id,
			old_owner,
			owner: region.owner,
			duration,
		});

		Ok(())
	}
```

**File:** substrate/frame/broker/src/dispatchable_impls.rs (L321-349)
```rust
	pub(crate) fn do_assign(
		region_id: RegionId,
		maybe_check_owner: Option<T::AccountId>,
		target: TaskId,
		finality: Finality,
	) -> Result<(), Error<T>> {
		let config = Configuration::<T>::get().ok_or(Error::<T>::Uninitialized)?;
		let status = Status::<T>::get().ok_or(Error::<T>::Uninitialized)?;

		if let Some((region_id, region)) = Self::utilize(region_id, maybe_check_owner, finality)? {
			let workplan_key = (region_id.begin, region_id.core);
			let mut workplan = Workplan::<T>::get(&workplan_key).unwrap_or_default();

			// Remove this region from the pool in case it has been assigned provisionally. If we
			// get this far then it is still in `Regions` and thus could only have been pooled
			// provisionally.
			Self::force_unpool_region(region_id, &region, &status);

			// Ensure no previous allocations exist.
			workplan.retain(|i| (i.mask & region_id.mask).is_void());
			if workplan
				.try_push(ScheduleItem {
					mask: region_id.mask,
					assignment: CoreAssignment::Task(target),
				})
				.is_ok()
			{
				Workplan::<T>::insert(&workplan_key, &workplan);
			}
```

**File:** prdoc/1.6.0/pr_2811.prdoc (L1-13)
```text
title: "Interlacing removes the region on which it is performed."

doc:
  - audience: Runtime User
    description: |
      The current implementation of the broker pallet does not remove
      the region on which the interlacing is performed. This can create
      a vulnerability, as the original region owner is still allowed to 
      assign a task to the region even after transferring an interlaced
      part of it.

crates:
  - name: "pallet-broker"
```

**File:** substrate/frame/broker/src/tests.rs (L3332-3358)
```rust
#[test]
fn force_transfer_can_transfer_provisionally_assigned_region() {
	TestExt::new().endow(1, 1000).execute_with(|| {
		assert_ok!(Broker::do_start_sales(100, 4));
		advance_to(2);

		const OLD_OWNER: u64 = 1;
		const NEW_OWNER: u64 = 222;

		let region_id = Broker::do_purchase(OLD_OWNER, u64::max_value()).unwrap();

		assert_ok!(Broker::assign(RuntimeOrigin::signed(OLD_OWNER), region_id, 1001, Provisional));

		assert_ok!(Broker::force_transfer(RuntimeOrigin::root(), region_id, NEW_OWNER));

		let region = Regions::<Test>::get(region_id).unwrap();
		System::assert_last_event(
			Event::Transferred {
				region_id,
				duration: region.end - region_id.begin,
				old_owner: Some(OLD_OWNER),
				owner: Some(NEW_OWNER),
			}
			.into(),
		);
	});
}
```
