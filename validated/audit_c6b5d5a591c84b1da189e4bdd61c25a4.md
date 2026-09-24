[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** substrate/frame/lottery/src/lib.rs (L481-509)
```rust
	/// Randomly choose a winning ticket and return the account that purchased it.
	/// The more tickets an account bought, the higher are its chances of winning.
	/// Returns `None` if there is no winner.
	fn choose_account() -> Option<T::AccountId> {
		match Self::choose_ticket(TicketsCount::<T>::get()) {
			None => None,
			Some(ticket) => Tickets::<T>::get(ticket),
		}
	}

	/// Randomly choose a winning ticket from among the total number of tickets.
	/// Returns `None` if there are no tickets.
	fn choose_ticket(total: u32) -> Option<u32> {
		if total == 0 {
			return None;
		}
		let mut random_number = Self::generate_random_number(0);

		// Best effort attempt to remove bias from modulus operator.
		for i in 1..T::MaxGenerateRandom::get() {
			if random_number < u32::MAX - u32::MAX % total {
				break;
			}

			random_number = Self::generate_random_number(i);
		}

		Some(random_number % total)
	}
```

**File:** substrate/frame/society/src/lib.rs (L1015-1040)
```rust
		/// As a member, vote on the defender.
		///
		/// The dispatch origin for this call must be _Signed_ and a member.
		///
		/// Parameters:
		/// - `approve`: A boolean which says if the candidate should be
		/// approved (`true`) or rejected (`false`).
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::defender_vote())]
		pub fn defender_vote(origin: OriginFor<T>, approve: bool) -> DispatchResultWithPostInfo {
			let voter = ensure_signed(origin)?;

			let mut defending = Defending::<T, I>::get().ok_or(Error::<T, I>::NoDefender)?;
			let record = Members::<T, I>::get(&voter).ok_or(Error::<T, I>::NotMember)?;

			let round = ChallengeRoundCount::<T, I>::get();
			let first_time = DefenderVotes::<T, I>::mutate(round, &voter, |v| {
				let first_time = v.is_none();
				*v = Some(Self::do_vote(*v, approve, record.rank, &mut defending.2));
				first_time
			});

			Defending::<T, I>::put(defending);
			Self::deposit_event(Event::<T, I>::DefenderVote { voter, vote: approve });
			Ok(if first_time { Pays::No } else { Pays::Yes }.into())
		}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L1408-1446)
```rust
	fn update_records(
		&mut self,
		id: PoolId,
		bonded_points: BalanceOf<T>,
		commission: Perbill,
	) -> Result<(), Error<T>> {
		let balance = Self::current_balance(id);

		let (current_reward_counter, new_pending_commission) =
			self.current_reward_counter(id, bonded_points, commission)?;

		// Store the reward counter at the time of this update. This is used in subsequent calls to
		// `current_reward_counter`, whereby newly pending rewards (in points) are added to this
		// value.
		self.last_recorded_reward_counter = current_reward_counter;

		// Add any new pending commission that has been calculated from `current_reward_counter` to
		// determine the total pending commission at the time of this update.
		self.total_commission_pending =
			self.total_commission_pending.saturating_add(new_pending_commission);

		// Total payouts are essentially the entire historical balance of the reward pool, equating
		// to the current balance + the total rewards that have left the pool + the total commission
		// that has left the pool.
		let last_recorded_total_payouts = balance
			.checked_add(&self.total_rewards_claimed.saturating_add(self.total_commission_claimed))
			.ok_or(Error::<T>::OverflowRisk)?;

		// Store the total payouts at the time of this update.
		//
		// An increase in ED could cause `last_recorded_total_payouts` to decrease but we should not
		// allow that to happen since an already paid out reward cannot decrease. The reward account
		// might go in deficit temporarily in this exceptional case but it will be corrected once
		// new rewards are added to the pool.
		self.last_recorded_total_payouts =
			self.last_recorded_total_payouts.max(last_recorded_total_payouts);

		Ok(())
	}
```

**File:** prdoc/pr_13182.prdoc (L1-12)
```text
title: 'core-fellowship: avoid panic on undersized Params salary/period vectors'
doc:
- audience: Runtime Dev
  description: |-
    `Pallet::get_salary` computed an index from the member's rank and then indexed the `active_salary `or `passive_salary` vector directly. The bump and promote calls did the same thing to `demotion_period `and `min_promotion_period`. All four of these vectors are BoundedVec fields bounded only by MaxRank, so a privileged set_params call is free to store a shorter vector, including the empty default. Once that happens, any of these three call sites panics for a member whose rank sits past the end of the stored vector, which traps the extrinsic instead of failing gracefully.

    This changes all three sites to look up the index with get and fall back to the type's default when the entry is missing, so a rank past the end of the vector now degrades to zero salary, a zero demotion period or a zero minimum promotion period, the same way the pallet already treats rank 0 and untracked members. No panic path remains.

    Closes #13141
crates:
- name: pallet-core-fellowship
  bump: patch
```
