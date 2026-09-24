No vulnerability found for this question.

The reported bug class—an unbounded `for` loop over all token holders in a push-based dividend distribution function that can be gas-bombed by an attacker minting to new addresses—does not have a demonstrable analog in this codebase, and the scan rules explicitly instruct rejecting "unbounded-loop or memory/storage-growth scenarios" as a bug class in any case.

Structurally, Substrate/FRAME already avoids the EVM anti-pattern the report warns about. Reward/dividend-like distribution in this codebase is implemented as pull-based, per-share accounting rather than iterate-all-holders push distribution:

- `pallet-staking`'s `payout_stakers` computes each nominator's share via `Perbill::from_rational` against a bounded, paged exposure list capped by `T::MaxExposurePageSize`, rather than iterating an unbounded holder set. [1](#0-0) [2](#0-1) 
- `pallet-nomination-pools` uses a per-share/point accumulator (`reward_pool`/`points`) so each member calls `claim_payout` individually to pull their share — exactly the "pointsPerShare" pattern the original report recommended as the fix — instead of a single call iterating every member. [3](#0-2) 
- `pallet-salary` similarly requires each claimant to call `do_payout` individually rather than a single admin call iterating all claimants. [4](#0-3) 
- `pallet-bags-list`'s rebagging logic explicitly bounds iteration per call using a `WeightMeter`/`rebag_budget` and resumable cursor to avoid unbounded work in a single block. [5](#0-4) 

Because FRAME's weight-metering model (not a fixed block gas limit) already requires bounded, benchmarked complexity for extrinsics, and dispatchables that would need to process an attacker-growable set are designed as paged/pull-based rather than single-call push loops, there is no reachable, unprivileged user entry point in this codebase matching the reported invariant violation (unbounded iteration over an attacker-inflatable holder set triggered by a single call).

### Citations

**File:** substrate/frame/staking/src/pallet/impls.rs (L373-391)
```rust
		// Let's now calculate how this is split to the nominators.
		// Reward only the clipped exposures. Note this is not necessarily sorted.
		for nominator in exposure.others().iter() {
			let nominator_exposure_part = Perbill::from_rational(nominator.value, exposure.total());

			let nominator_reward: BalanceOf<T> =
				nominator_exposure_part * validator_leftover_payout;
			// We can now make nominator payout:
			if let Some((imbalance, dest)) = Self::make_payout(&nominator.who, nominator_reward) {
				// Note: this logic does not count payouts for `RewardDestination::None`.
				nominator_payout_count += 1;
				let e = Event::<T>::Rewarded {
					stash: nominator.who.clone(),
					dest,
					amount: imbalance.peek(),
				};
				Self::deposit_event(e);
				total_imbalance.subsume(imbalance);
			}
```

**File:** substrate/frame/staking/src/pallet/mod.rs (L1729-1738)
```rust
		#[pallet::call_index(18)]
		#[pallet::weight(T::WeightInfo::payout_stakers_alive_staked(T::MaxExposurePageSize::get()))]
		pub fn payout_stakers(
			origin: OriginFor<T>,
			validator_stash: T::AccountId,
			era: EraIndex,
		) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;
			Self::do_payout_stakers(validator_stash, era)
		}
```

**File:** substrate/frame/nomination-pools/src/tests.rs (L1216-1226)
```rust
				assert_ok!(Pools::claim_payout(RuntimeOrigin::signed(10)));

				// Then
				assert_eq!(
					pool_events_since_last_call(),
					vec![Event::PaidOut { member: 10, pool_id: 1, payout: 2 }]
				);
				assert_eq!(PoolMembers::<Runtime>::get(10).unwrap(), del_float(10, 6.2));
				assert_eq!(RewardPools::<Runtime>::get(1).unwrap(), rew(0, 0, 222));
				assert_eq!(Currency::free_balance(&10), 60 + 2);
				assert_eq!(Currency::free_balance(&default_reward_account()), ed + 398);
```

**File:** substrate/frame/salary/src/lib.rs (L382-438)
```rust
		fn do_payout(who: T::AccountId, beneficiary: T::AccountId) -> DispatchResult {
			let mut status = Status::<T, I>::get().ok_or(Error::<T, I>::NotStarted)?;
			let mut claimant = Claimant::<T, I>::get(&who).ok_or(Error::<T, I>::NotInducted)?;

			let now = frame_system::Pallet::<T>::block_number();
			ensure!(
				now >= status.cycle_start + T::RegistrationPeriod::get(),
				Error::<T, I>::TooEarly,
			);

			let (payout, registered) = match claimant.status {
				Registered(unpaid) if claimant.last_active == status.cycle_index => {
					// Registered for this cycle. Pay accordingly.
					let payout = if status.total_registrations <= status.budget {
						// Can pay in full.
						unpaid
					} else {
						// Must be reduced pro-rata
						Perbill::from_rational(status.budget, status.total_registrations)
							.mul_floor(unpaid)
					};
					(payout, Some(unpaid))
				},
				Nothing | Attempted { .. } | Registered(_)
					if claimant.last_active < status.cycle_index =>
				{
					// Not registered for this cycle (or stale registration from previous cycle).
					// Pay from whatever is left.
					let rank = T::Members::rank_of(&who).ok_or(Error::<T, I>::NotMember)?;
					let ideal_payout = T::Salary::get_salary(rank, &who);

					let pot = status
						.budget
						.saturating_sub(status.total_registrations)
						.saturating_sub(status.total_unregistered_paid);

					let payout = ideal_payout.min(pot);
					ensure!(!payout.is_zero(), Error::<T, I>::ClaimZero);

					status.total_unregistered_paid.saturating_accrue(payout);
					(payout, None)
				},
				_ => return Err(Error::<T, I>::NoClaim.into()),
			};

			claimant.last_active = status.cycle_index;

			let id =
				T::Paymaster::pay(&beneficiary, (), payout).map_err(|_| Error::<T, I>::PayError)?;

			claimant.status = Attempted { registered, id, amount: payout };

			Claimant::<T, I>::insert(&who, &claimant);
			Status::<T, I>::put(&status);

			Self::deposit_event(Event::<T, I>::Paid { who, beneficiary, amount: payout, id });
			Ok(())
```

**File:** substrate/frame/bags-list/src/lib.rs (L507-544)
```rust
			let mut processed = 0u32;
			let mut successful_rebags = 0u32;
			let mut failed_rebags = 0u32;
			let mut pending_processed = 0u32;

			// First item's weight was already consumed above.
			for (i, account) in to_process.iter().enumerate() {
				// Consume weight for every item after the first.
				if i > 0 && meter.try_consume(per_item).is_err() {
					break;
				}

				let pending_value = if PendingRebag::<T, I>::contains_key(account) { 1 } else { 0 };

				match Self::rebag_internal(account) {
					Err(Error::<T, I>::Locked) => {
						defensive!("Pallet became locked during auto-rebag, stopping");
						break;
					},
					Err(e) => {
						log!(warn, "Error during rebagging: {:?}", e);
						failed_rebags += 1;
					},
					Ok(Some((from, to))) => {
						log!(debug, "Rebagged {:?}: moved from {:?} to {:?}", account, from, to);
						successful_rebags += 1;
						pending_processed += pending_value;
					},
					Ok(None) => {
						log!(debug, "Rebagging not needed for {:?}", account);
						pending_processed += pending_value;
					},
				}

				processed += 1;
				if processed == rebag_budget {
					break;
				}
```
