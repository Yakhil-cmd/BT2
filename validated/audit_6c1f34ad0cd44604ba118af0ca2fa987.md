Based on my research, I found a genuine structural analog in `substrate/frame/nomination-pools`, though I was unable to fully trace the `payout_stakers` → reward-account wiring or execute a live reproduction within this read-only session. I present the finding with those limitations disclosed, as the strict-execution requirement (step 6) could not be satisfied in ask-only mode.

### Title
Nomination-pool reward attribution is based on current points at settlement time, not time-weighted contribution, allowing a large last-moment `bond_extra` to capture rewards accrued by other members - ([File: substrate/frame/nomination-pools/src/lib.rs])

### Summary
Ajna's `RewardsManager` was reported sandwichable because staking rewards are attributed based on the exchange-rate/epoch state read at claim time, not the staker's actual time-in-position, and there is no fee or warm-up period. `pallet-nomination-pools` uses an analogous "reward counter" accounting scheme (`RewardPool::current_reward_counter` / `update_records`) where the share of any newly-arrived reward balance is divided among whichever `bonded_points` exist at the moment a checkpoint is taken (triggered by any `join`, `bond_extra`, `unbond`, or `claim_payout` call), not by how long each member's points were actually staked during the accrual window [1](#0-0) . There is no fee or lock-up on `bond_extra`/`claim_payout` analogous to the Ajna report's missing warm-up period [2](#0-1) .

### Finding Description
`current_reward_counter` computes the pool's undistributed balance since the last checkpoint (`current_payout_balance = balance + total_rewards_claimed + total_commission_claimed - last_recorded_total_payouts`) and divides it by the `bonded_points` passed in as of the *current* call, then adds it to `last_recorded_reward_counter` [3](#0-2) . Each member's claimable amount is `(current_reward_counter - member.last_recorded_reward_counter) * member.active_points`, computed in `do_reward_payout` [4](#0-3) .

Crucially, when a member calls `bond_extra`/`join`, the pallet calls `reward_pool.update_records` with the *old* (pre-change) points to snapshot a fair baseline before the point increase is applied, then sets the member's `last_recorded_reward_counter` to that same value [5](#0-4) . This correctly stops a joiner from claiming rewards that already landed *before* their join. However, it does not protect against the inverse timing: if an attacker bonds a large amount immediately *before* a new reward inflow lands in the reward account (e.g. from an era's staking payout being credited to the pool's dedicated reward destination), and then a checkpoint is triggered (by anyone) after that inflow, the attacker's now-large `bonded_points` participates fully in dividing that newly-arrived reward - exactly as if they had been staked for the entire accrual period, even though their capital was only present for one checkpoint interval. `bond_extra` and `claim_payout` carry no fee, cooldown, or minimum holding period [6](#0-5) .

### Impact Explanation
If validated end-to-end, this would let an attacker with sufficient capital dilute the reward share of long-term nomination-pool members by bonding extra just ahead of a payout settlement and immediately claiming a disproportionate cut, then beginning to unbond. This is a value-transfer / unfair-distribution issue among pool members rather than unbacked issuance, since the total distributed never exceeds the pool's actual accumulated reward balance.

### Likelihood Explanation
Uncertain / not established. Two conditions I could not verify in this session materially affect exploitability:
1. Whether staking-pool payouts (`payout_stakers`/`payout_stakers_by_page`) can be triggered permissionlessly by anyone at an attacker-chosen moment and whether they deposit as a discrete lump sum into the pool's reward account in a way an attacker can time precisely against their own `bond_extra` and `claim_payout` calls - I found the relevant functions in `substrate/frame/staking/src/pallet/mod.rs` and `substrate/frame/staking-async/src/pallet/mod.rs` but did not trace the full `Payee`/reward-destination wiring back to the pool's reward account.
2. The attacker's principal used for the outsized `bond_extra` remains locked/subject to slashing for the full unbonding duration, which is a real economic cost absent in the EVM analog (no lockup at all in Ajna). This materially changes attacker economics and could make the attack unprofitable or self-limiting in most cases, unlike the frictionless single-block sandwich in the original report.

Given these open questions, I cannot confirm this rises to a demonstrable, in-scope vulnerability at this time.

### Recommendation
If confirmed reachable, consider time-weighting reward attribution (e.g., accruing rewards per-block proportional to points held during each block, as `pallet-asset-rewards` does via `reward_per_token_stored`/`last_update_block` [7](#0-6) ) rather than settling entirely on point-share at checkpoint time, or introduce a minimum bonding duration before newly bonded points participate in pending reward distributions.

### Proof of Concept
Not executed. This tool session is read-only (no compiler/test-runner access), so no local Rust/FRAME integration test was run to confirm the attack end-to-end. The analysis above is a code-level trace of `update_records`/`current_reward_counter`/`do_reward_payout` in `substrate/frame/nomination-pools/src/lib.rs`; it does not constitute a proven exploit. A background Devin session with repository and test-execution access would be needed to (a) trace the `payout_stakers` → reward-account deposit path, (b) write an integration test that bonds a large `bond_extra` immediately before a payout lands and asserts a disproportionate `claim_payout` result, and (c) determine whether the locked-principal/slashing-risk cost neutralizes the attack in practice.

### Citations

**File:** substrate/frame/nomination-pools/src/lib.rs (L1402-1446)
```rust
	/// Update the recorded values of the reward pool.
	///
	/// This function MUST be called whenever the points in the bonded pool change, AND whenever the
	/// the pools commission is updated. The reason for the former is that a change in pool points
	/// will alter the share of the reward balance among pool members, and the reason for the latter
	/// is that a change in commission will alter the share of the reward balance among the pool.
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

**File:** substrate/frame/nomination-pools/src/lib.rs (L1456-1511)
```rust
		let balance = Self::current_balance(id);

		// Calculate the current payout balance. The first 3 values of this calculation added
		// together represent what the balance would be if no payouts were made. The
		// `last_recorded_total_payouts` is then subtracted from this value to cancel out previously
		// recorded payouts, leaving only the remaining payouts that have not been claimed.
		let current_payout_balance = balance
			.saturating_add(self.total_rewards_claimed)
			.saturating_add(self.total_commission_claimed)
			.saturating_sub(self.last_recorded_total_payouts);

		// Split the `current_payout_balance` into claimable rewards and claimable commission
		// according to the current commission rate.
		let new_pending_commission = commission * current_payout_balance;
		let new_pending_rewards = current_payout_balance.saturating_sub(new_pending_commission);

		// * accuracy notes regarding the multiplication in `checked_from_rational`:
		// `current_payout_balance` is a subset of the total_issuance at the very worse.
		// `bonded_points` are similarly, in a non-slashed pool, have the same granularity as
		// balance, and are thus below within the range of total_issuance. In the worse case
		// scenario, for `saturating_from_rational`, we have:
		//
		// dot_total_issuance * 10^18 / `minJoinBond`
		//
		// assuming `MinJoinBond == ED`
		//
		// dot_total_issuance * 10^18 / 10^10 = dot_total_issuance * 10^8
		//
		// which, with the current numbers, is a miniscule fraction of the u128 capacity.
		//
		// Thus, adding two values of type reward counter should be safe for ages in a chain like
		// Polkadot. The important note here is that `reward_pool.last_recorded_reward_counter` only
		// ever accumulates, but its semantics imply that it is less than total_issuance, when
		// represented as `FixedU128`, which means it is less than `total_issuance * 10^18`.
		//
		// * accuracy notes regarding `checked_from_rational` collapsing to zero, meaning that no
		//   reward can be claimed:
		//
		// largest `bonded_points`, such that the reward counter is non-zero, with `FixedU128` will
		// be when the payout is being computed. This essentially means `payout/bonded_points` needs
		// to be more than 1/1^18. Thus, assuming that `bonded_points` will always be less than `10
		// * dot_total_issuance`, if the reward_counter is the smallest possible value, the value of
		//   the
		// reward being calculated is:
		//
		// x / 10^20 = 1/ 10^18
		//
		// x = 100
		//
		// which is basically 10^-8 DOTs. See `smallest_claimable_reward` for an example of this.
		let current_reward_counter =
			T::RewardCounter::checked_from_rational(new_pending_rewards, bonded_points)
				.and_then(|ref r| self.last_recorded_reward_counter.checked_add(r))
				.ok_or(Error::<T>::OverflowRisk)?;

		Ok((current_reward_counter, new_pending_commission))
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L2100-2158)
```rust
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Stake funds with a pool. The amount to bond is delegated (or transferred based on
		/// [`adapter::StakeStrategyType`]) from the member to the pool account and immediately
		/// increases the pool's bond.
		///
		/// The method of transferring the amount to the pool account is determined by
		/// [`adapter::StakeStrategyType`]. If the pool is configured to use
		/// [`adapter::StakeStrategyType::Delegate`], the funds remain in the account of
		/// the `origin`, while the pool gains the right to use these funds for staking.
		///
		/// # Note
		///
		/// * An account can only be a member of a single pool.
		/// * An account cannot join the same pool multiple times.
		/// * This call will *not* dust the member account, so the member must have at least
		///   `existential deposit + amount` in their account.
		/// * Only a pool with [`PoolState::Open`] can be joined
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::join())]
		pub fn join(
			origin: OriginFor<T>,
			#[pallet::compact] amount: BalanceOf<T>,
			pool_id: PoolId,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// ensure pool is not in an un-migrated state.
			ensure!(!Self::api_pool_needs_delegate_migration(pool_id), Error::<T>::NotMigrated);

			// ensure account is not restricted from joining the pool.
			ensure!(!T::Filter::contains(&who), Error::<T>::Restricted);

			ensure!(amount >= MinJoinBond::<T>::get(), Error::<T>::MinimumBondNotMet);
			// If a member already exists that means they already belong to a pool
			ensure!(!PoolMembers::<T>::contains_key(&who), Error::<T>::AccountBelongsToOtherPool);

			let mut bonded_pool = BondedPool::<T>::get(pool_id).ok_or(Error::<T>::PoolNotFound)?;
			bonded_pool.ok_to_join()?;

			let mut reward_pool = RewardPools::<T>::get(pool_id)
				.defensive_ok_or::<Error<T>>(DefensiveError::RewardPoolNotFound.into())?;
			// IMPORTANT: reward pool records must be updated with the old points.
			reward_pool.update_records(
				pool_id,
				bonded_pool.points,
				bonded_pool.commission.current(),
			)?;

			bonded_pool.try_inc_members()?;
			let points_issued = bonded_pool.try_bond_funds(&who, amount, BondType::Extra)?;

			PoolMembers::insert(
				who.clone(),
				PoolMember::<T> {
					pool_id,
					points: points_issued,
					// we just updated `last_known_reward_counter` to the current one in
					// `update_recorded`.
					last_recorded_reward_counter: reward_pool.last_recorded_reward_counter(),
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3539-3554)
```rust
		let (current_reward_counter, _) = reward_pool.current_reward_counter(
			bonded_pool.id,
			bonded_pool.points,
			bonded_pool.commission.current(),
		)?;

		// Determine the pending rewards. In scenarios where commission is 100%, `pending_rewards`
		// will be zero.
		let pending_rewards = member.pending_rewards(current_reward_counter)?;
		if pending_rewards.is_zero() {
			return Ok(pending_rewards);
		}

		// IFF the reward is non-zero alter the member and reward pool info.
		member.last_recorded_reward_counter = current_reward_counter;
		reward_pool.register_claimed_reward(pending_rewards);
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L473-502)
```rust
		pub fn stake(origin: OriginFor<T>, pool_id: PoolId, amount: T::Balance) -> DispatchResult {
			let staker = ensure_signed(origin)?;

			// Always start by updating staker and pool rewards.
			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			let staker_info = PoolStakers::<T>::get(pool_id, &staker).unwrap_or_default();
			let (mut pool_info, mut staker_info) =
				Self::update_pool_and_staker_rewards(&pool_info, &staker_info)?;

			T::AssetsFreezer::increase_frozen(
				pool_info.staked_asset_id.clone(),
				&FreezeReason::Staked.into(),
				&staker,
				amount,
			)?;

			// Update Pools.
			pool_info.total_tokens_staked.ensure_add_assign(amount)?;

			Pools::<T>::insert(pool_id, pool_info);

			// Update PoolStakers.
			staker_info.amount.ensure_add_assign(amount)?;
			PoolStakers::<T>::insert(pool_id, &staker, staker_info);

			// Emit event.
			Self::deposit_event(Event::Staked { staker, pool_id, amount });

			Ok(())
		}
```
