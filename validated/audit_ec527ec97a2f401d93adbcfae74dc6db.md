[1](#0-0) [2](#0-1)

### Citations

**File:** substrate/frame/nomination-pools/src/lib.rs (L1391-1446)
```rust
impl<T: Config> RewardPool<T> {
	/// Getter for [`RewardPool::last_recorded_reward_counter`].
	pub(crate) fn last_recorded_reward_counter(&self) -> T::RewardCounter {
		self.last_recorded_reward_counter
	}

	/// Register some rewards that are claimed from the pool by the members.
	fn register_claimed_reward(&mut self, reward: BalanceOf<T>) {
		self.total_rewards_claimed = self.total_rewards_claimed.saturating_add(reward);
	}

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

**File:** substrate/frame/staking-async/src/pallet/impls.rs (L678-758)
```rust
	/// Calculate the validator incentive amount for a single page.
	///
	/// Computes the validator's slice of the era incentive budget for one payout page:
	/// `share × budget × page_stake_part`.
	///
	/// The share formula is the weighted-points share
	/// `(weight_stash · ep_stash) / Σ_v(weight_v · ep_v)`, with the denominator read from
	/// [`ErasSumWeightedPoints`]. Pre-cutoff eras instead use the legacy stake-only share
	/// `weight_stash / Σ weight`; see [`Eras::uses_weighted_points`] for which eras fall on
	/// which side and why.
	///
	/// Returns `None` if the validator has no incentive weight, no era points, or the
	/// computed amount rounds to zero.
	fn calculate_validator_incentive_for_page(
		era: EraIndex,
		stash: &T::AccountId,
		page_stake_part: Perbill,
		era_reward_points: &EraRewardPoints<T>,
	) -> Option<BalanceOf<T>> {
		let era_incentive_budget = Eras::<T>::get_validator_incentive_budget(era);
		if era_incentive_budget.is_zero() {
			return None;
		}

		let validator_weight = match ErasValidatorIncentiveWeight::<T>::get(era, stash) {
			// No incentive weight (e.g. own-stake was zero at election) means no share.
			Some(w) if !w.is_zero() => w,
			_ => return None,
		};

		// Branch on the cutoff: legacy formula for eras whose denominator was never
		// maintained, new weighted-points formula otherwise.
		let share_part = if Eras::<T>::uses_weighted_points(era) {
			// This validator has non-zero weight (checked above) and reached this point only
			// with non-zero reward points (gated by the caller), so it must have contributed
			// to the denominator. A zero denominator with a live budget is therefore a storage
			// inconsistency and is surfaced rather than silently paying nothing.
			let sum_weighted_points = ErasSumWeightedPoints::<T>::get(era);
			if sum_weighted_points.is_zero() {
				log!(warn, "Sum of weighted points is zero but budget exists for era {}", era);
				Self::deposit_event(Event::<T>::Unexpected(
					UnexpectedKind::ValidatorIncentiveWeightMismatch { era },
				));
				return None;
			}
			let validator_points: RewardPoint =
				era_reward_points.individual.get(stash).copied().unwrap_or(0);
			let numerator = validator_weight.saturating_mul(BalanceOf::<T>::from(validator_points));
			Perbill::from_rational(numerator, sum_weighted_points)
		} else {
			// Legacy stake-only share, denominated by the total incentive weight across all
			// elected validators. A zero denominator with a non-zero budget is a storage
			// inconsistency, so it is surfaced rather than silently paying nothing.
			let total_weight = ErasSumValidatorIncentiveWeight::<T>::get(era);
			if total_weight.is_zero() {
				log!(
					warn,
					"Total validator incentive weight is zero but budget exists for era {}",
					era
				);
				Self::deposit_event(Event::<T>::Unexpected(
					UnexpectedKind::ValidatorIncentiveWeightMismatch { era },
				));
				return None;
			}
			Perbill::from_rational(validator_weight, total_weight)
		};

		if share_part.is_zero() {
			return None;
		}

		let validator_total_incentive = share_part.mul_floor(era_incentive_budget);
		let validator_incentive_for_page = page_stake_part.mul_floor(validator_total_incentive);

		if validator_incentive_for_page.is_zero() {
			return None;
		}

		Some(validator_incentive_for_page)
	}
```
