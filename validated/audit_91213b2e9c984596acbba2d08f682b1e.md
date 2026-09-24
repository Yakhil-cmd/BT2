### Title
`pallet-broker::renew` lets any signed account pay to renew another task's core without receiving the resulting Region or workload benefit - (File: substrate/frame/broker/src/lib.rs)

### Summary
The `renew` extrinsic in `pallet-broker` can be called by any signed account for any `CoreIndex` that has a pending `PotentialRenewals` entry, and the caller pays the renewal price from their own balance. Unlike `do_purchase`, `do_renew` never mints/assigns a Region to the caller — the renewed workload keeps serving whatever `task` was already recorded for that core. If the caller is not the original task's controller/sovereign account, they pay real funds and get nothing back, mirroring the structural flaw in the `Cooler.rollLoan` report: an unauthenticated caller can be charged for a benefit that accrues to someone else.

### Finding Description
`renew` is a plain signed extrinsic with no ownership check on `core`: [1](#0-0) 

It forwards straight to `do_renew(who, core)`: [2](#0-1) 

`do_renew` looks up the `PotentialRenewalRecord` keyed only by `core` (not by `who`), charges `who` via `purchase_core`, and then re-inserts the *existing* `workload` (which references a specific `task`, e.g. task `2001` from the recorded renewal) into `Workplan` for the new core: [3](#0-2) 

Compare this to `do_purchase`, which does mint an owned `Region` for the payer via `Self::issue(..., Some(who.clone()), ...)`: [4](#0-3) 

`do_renew` has no equivalent `issue()` call — no Region asset is created for `who`. The only state that changes in the caller's favor is the `PotentialRenewals` entry for the *next* renewal cycle, which is still keyed to the same `core`/`task`, not to `who`.

Critically, the pallet authors *do* recognize that "paying to renew another task's workload" is a bug — they patched exactly this class of issue for the `enable_auto_renew`/auto-renewal path: [5](#0-4) 

That fix (see the "[pallet-broker] Prevent auto-renewal from renewing another task's workload" PR) added an explicit `ensure!(who == sovereign_account, Error::<T>::NoPermission)` check plus a `is_complete_and_contains_task` verification before charging. No such check exists in the plain `renew(origin, core)` call path used by `do_renew`, which any signed account can invoke for any core with a pending renewal, regardless of who owns/controls the task on that core.

### Impact Explanation
Any signed account can call `renew(origin, core)` for a `core` index whose `PotentialRenewals` record belongs to an unrelated task/owner. The caller's balance is debited for `record.price` (via `purchase_core`), but:
- No Region is minted or transferred to the caller (unlike `do_purchase`).
- The renewed workload continues serving the original `task`, not the caller.

This is a direct funds-loss-without-benefit condition for any user who mistakenly (or is tricked into) calling `renew` for a core they do not control — functionally identical to the `Cooler.rollLoan` issue where a non-borrower caller sends value and receives nothing in return. Severity is Medium: it requires a mistaken/confused caller (no privileged role, no stolen keys), and the loss is bounded to the renewal price paid, but it is a real, deterministic loss of funds with no compensating state change for the payer.

### Likelihood Explanation
The `renew` extrinsic is a standard, unprivileged signed call, and would be reachable on any runtime including `pallet-broker` (Coretime parachains). Because `renew` doesn't require the caller to be the original purchaser/task owner (documented as "Must be a Signed origin with at least enough funds to pay the renewal price of the core", with no mention of ownership), and coretime cores/tasks are identified purely by numeric `CoreIndex`, an inattentive user could easily call `renew` with the wrong `core` value copied from elsewhere, or be induced to do so (e.g. via a scam UI claiming "renew core X for a discount"), losing funds with the benefit accruing to a third party's task. Likelihood is Medium given it depends on user/caller error rather than an active exploit against a victim.

### Recommendation
Restrict `renew` (or `do_renew`) to require that the caller is the party entitled to benefit from the renewed workload — e.g., require `who` to match the sovereign/controlling account of the `task` referenced in the `PotentialRenewalRecord` for `core`, mirroring the check already added to `enable_auto_renew`:
```rust
pub fn renew(origin: OriginFor<T>, core: CoreIndex) -> DispatchResultWithPostInfo {
    let who = ensure_signed(origin)?;
    let record = PotentialRenewals::<T>::get(PotentialRenewalId { core, when: ... })
        .ok_or(Error::<T>::NotAllowed)?;
    let workload = record.completion.complete().ok_or(Error::<T>::IncompleteAssignment)?;
    ensure!(
        workload.iter().any(|item| Self::caller_owns_task(&who, item.assignment)),
        Error::<T>::NoPermission
    );
    Self::do_renew(who, core)?;
    Ok(Pays::No.into())
}
```
Alternatively, mint/transfer a Region to the payer on renewal (as `do_purchase` does) so that any account calling `renew` at least receives a fungible/tradeable asset for the price paid, removing the "pay with nothing in return" condition entirely.

### Proof of Concept
No executed reproduction was run (no terminal/test-execution access in this environment); this is a static-analysis-based analog, not a confirmed live exploit. The relevant guards were traced statically:
- `renew` extrinsic: no ownership/permission check before charging (`substrate/frame/broker/src/lib.rs:735-740`).
- `do_renew`: charges `who` via `purchase_core`, reuses the pre-existing `workload`/`task` from `PotentialRenewals`, and does **not** call `Self::issue()` to grant `who` any Region (`substrate/frame/broker/src/dispatchable_impls.rs:179-227`), unlike `do_purchase` which does (`dispatchable_impls.rs:149-176`).
- The equivalent permission check exists for the auto-renewal path (`enable_auto_renew`, `lib.rs:964-981`), confirming the project's own recognition of this exact bug class ("a task could end up paying to renew a completely unrelated task's workload" — `prdoc/stable2606-2/pr_12750.prdoc`), but the fix was not applied to the plain `renew` extrinsic.

A minimal local integration test to confirm this concretely (not executed here) would:
1. Set up two accounts, `A` (task owner) and `B` (unrelated caller), start a sale, and create a renewable core/task for `A` (as in `leases_can_be_renewed`, `substrate/frame/broker/src/tests.rs:1620-1655`).
2. Advance to the renewal window, then call `Broker::renew(RuntimeOrigin::signed(B), core)`.
3. Assert `do_renew` succeeds, `B`'s balance decreases by `record.price`, and assert `B` receives no `Region` (`Regions::<Test>::iter().find(|(_, r)| r.owner == Some(B))` is `None`) while the workload for `A`'s task continues unchanged.

Given the lack of execution, this should be treated as a strong structural analog requiring confirmation via an actual Devin session/test run before being escalated as a confirmed, bounty-eligible finding.

### Citations

**File:** substrate/frame/broker/src/lib.rs (L730-740)
```rust
		/// Renew Bulk Coretime in the ongoing Sale or its prior Interlude Period.
		///
		/// - `origin`: Must be a Signed origin with at least enough funds to pay the renewal price
		///   of the core.
		/// - `core`: The core which should be renewed.
		#[pallet::call_index(6)]
		pub fn renew(origin: OriginFor<T>, core: CoreIndex) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;
			Self::do_renew(who, core)?;
			Ok(Pays::No.into())
		}
```

**File:** substrate/frame/broker/src/lib.rs (L964-981)
```rust
		#[pallet::call_index(21)]
		#[pallet::weight(T::WeightInfo::enable_auto_renew())]
		pub fn enable_auto_renew(
			origin: OriginFor<T>,
			core: CoreIndex,
			task: TaskId,
			workload_end_hint: Option<Timeslice>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let sovereign_account = T::SovereignAccountOf::maybe_convert(task)
				.ok_or(Error::<T>::SovereignAccountNotFound)?;
			// Only the sovereign account of a task can enable auto renewal for its own core.
			ensure!(who == sovereign_account, Error::<T>::NoPermission);

			Self::do_enable_auto_renew(sovereign_account, core, task, workload_end_hint)?;
			Ok(())
		}
```

**File:** substrate/frame/broker/src/dispatchable_impls.rs (L149-176)
```rust
	pub(crate) fn do_purchase(
		who: T::AccountId,
		price_limit: BalanceOf<T>,
	) -> Result<RegionId, DispatchError> {
		let status = Status::<T>::get().ok_or(Error::<T>::Uninitialized)?;
		let mut sale = SaleInfo::<T>::get().ok_or(Error::<T>::NoSales)?;
		Self::ensure_cores_for_sale(&status, &sale)?;

		let now = RCBlockNumberProviderOf::<T::Coretime>::current_block_number();
		ensure!(now > sale.sale_start, Error::<T>::TooEarly);
		let price = Self::sale_price(&sale, now);
		ensure!(price_limit >= price, Error::<T>::Overpriced);

		let core = Self::purchase_core(&who, price, &mut sale)?;

		SaleInfo::<T>::put(&sale);
		let id = Self::issue(
			core,
			sale.region_begin,
			CoreMask::complete(),
			sale.region_end,
			Some(who.clone()),
			Some(price),
		);
		let duration = sale.region_end.saturating_sub(sale.region_begin);
		Self::deposit_event(Event::Purchased { who, region_id: id, price, duration });
		Ok(id)
	}
```

**File:** substrate/frame/broker/src/dispatchable_impls.rs (L179-227)
```rust
	/// current sale status's `region_end`.
	pub(crate) fn do_renew(who: T::AccountId, core: CoreIndex) -> Result<CoreIndex, DispatchError> {
		let config = Configuration::<T>::get().ok_or(Error::<T>::Uninitialized)?;
		let status = Status::<T>::get().ok_or(Error::<T>::Uninitialized)?;
		let mut sale = SaleInfo::<T>::get().ok_or(Error::<T>::NoSales)?;
		Self::ensure_cores_for_sale(&status, &sale)?;

		let renewal_id = PotentialRenewalId { core, when: sale.region_begin };
		let record = PotentialRenewals::<T>::get(renewal_id).ok_or(Error::<T>::NotAllowed)?;
		let workload =
			record.completion.drain_complete().ok_or(Error::<T>::IncompleteAssignment)?;

		let old_core = core;

		let core = Self::purchase_core(&who, record.price, &mut sale)?;

		Self::deposit_event(Event::Renewed {
			who,
			old_core,
			core,
			price: record.price,
			begin: sale.region_begin,
			duration: sale.region_end.saturating_sub(sale.region_begin),
			workload: workload.clone(),
		});

		Workplan::<T>::insert((sale.region_begin, core), &workload);

		let begin = sale.region_end;
		let end_price = sale.end_price;
		// Renewals should never be priced lower than the current `end_price`:
		let price_cap = cmp::max(record.price + config.renewal_bump * record.price, end_price);
		let now = RCBlockNumberProviderOf::<T::Coretime>::current_block_number();
		let price = Self::sale_price(&sale, now).min(price_cap);
		log::debug!(
			"Renew with: sale price: {:?}, price cap: {:?}, old price: {:?}",
			price,
			price_cap,
			record.price
		);
		let new_record = PotentialRenewalRecord { price, completion: Complete(workload) };
		PotentialRenewals::<T>::remove(renewal_id);
		PotentialRenewals::<T>::insert(PotentialRenewalId { core, when: begin }, &new_record);
		SaleInfo::<T>::put(&sale);
		if let Some(workload) = new_record.completion.drain_complete() {
			log::debug!("Recording renewable price for next run: {:?}", price);
			Self::deposit_event(Event::Renewable { core, price, begin, workload });
		}
		Ok(core)
```
