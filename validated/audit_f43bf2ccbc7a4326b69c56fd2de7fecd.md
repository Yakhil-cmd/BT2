No vulnerability found for this question.

The report's root cause is purely a transaction-ordering/economic effect: the `nuke()` payout is a proportional share of a shared pool that shrinks as other users claim first, and the "fix" the reporter dismisses (min-claim/slippage check) does not point to any deterministic accounting bug — it's the same "first-come-first-served" resource-pool nature that Polkadot's own share-based payout mechanisms (e.g., nomination-pools reward accounting via `RewardPool::update_records`/`current_reward_counter` and `do_reward_payout`, and the broker's `do_claim_revenue`) are intentionally built around [1](#0-0) [2](#0-1) . In these FRAME systems, later claimants receiving a different amount than an earlier claimant "would have" gotten if ordered differently is expected, protocol-defined behavior (rewards/payouts are computed from the state *at the time of dispatch*, and extrinsic ordering within a block is determined by the block author under consensus rules, not by an adversarial mempool as in the EVM/Base L2 report) [3](#0-2) .

The scan methodology explicitly instructs to "reject ... pure front-running/economic attacks" (rule 5), and this report's entire premise — that the *order* of two legitimate, correctly-computed claims on a shared pool changes the payout each receives — is exactly that category, not a checks/mutation/authorization defect. No unbacked issuance, unauthorized dispatch, or integrity break was found; the analogous FRAME payout/share-dissolution logic (`withdraw_unbonded`, `SubPools::dissolve`, `InstaPoolHistory` payout math) is deterministic, bounded, and matches its documented specification [4](#0-3) .

### Citations

**File:** substrate/frame/nomination-pools/src/lib.rs (L287-302)
```rust
//! When a member initiates unbonding it's claim on the bonded pool (`balance_to_unbond`) is
//! computed as:
//!
//! ```text
//! balance_to_unbond = (bonded_pool.balance / bonded_pool.points) * member.points;
//! ```
//!
//! If this is the first transfer into an unbonding pool arbitrary amount of points can be issued
//! per balance. In this implementation unbonding pools are initialized with a 1 point to 1 balance
//! ratio (see [`POINTS_TO_BALANCE_INIT_RATIO`]). Otherwise, the unbonding pools hold the same
//! points to balance ratio properties as the bonded pool, so member points in the unbonding pool
//! are issued based on
//!
//! ```text
//! new_points_issued = (points_before_transfer / balance_before_transfer) * balance_to_unbond;
//! ```
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L1402-1417)
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
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L2469-2496)
```rust
			let mut sum_unlocked_points: BalanceOf<T> = Zero::zero();
			let balance_to_unbond = withdrawn_points
				.iter()
				.fold(BalanceOf::<T>::zero(), |accumulator, (era, unlocked_points)| {
					sum_unlocked_points = sum_unlocked_points.saturating_add(*unlocked_points);
					if let Some(era_pool) = sub_pools.with_era.get_mut(era) {
						let balance_to_unbond = era_pool.dissolve(*unlocked_points);
						if era_pool.points.is_zero() {
							sub_pools.with_era.remove(era);
						}
						accumulator.saturating_add(balance_to_unbond)
					} else {
						// A pool does not belong to this era, so it must have been merged to the
						// era-less pool.
						accumulator.saturating_add(sub_pools.no_era.dissolve(*unlocked_points))
					}
				})
				// A call to this transaction may cause the pool's stash to get dusted. If this
				// happens before the last member has withdrawn, then all subsequent withdraws will
				// be 0. However the unbond pools do no get updated to reflect this. In the
				// aforementioned scenario, this check ensures we don't try to withdraw funds that
				// don't exist. This check is also defensive in cases where the unbond pool does not
				// update its balance (e.g. a bug in the slashing hook.) We gracefully proceed in
				// order to ensure members can leave the pool and it can be destroyed.
				.min(T::StakeAdapter::transferable_balance(
					Pool::from(bonded_pool.bonded_account()),
					Member::from(member_account.clone()),
				));
```

**File:** substrate/frame/broker/src/dispatchable_impls.rs (L436-452)
```rust
			let Some(mut pool_record) = InstaPoolHistory::<T>::get(r) else { continue };
			let Some(total_payout) = pool_record.maybe_payout else { break };
			let p = total_payout
				.saturating_mul(contributed_parts.into())
				.checked_div(&pool_record.private_contributions.into())
				.unwrap_or_default();

			payout.saturating_accrue(p);
			pool_record.private_contributions.saturating_reduce(contributed_parts);

			let remaining_payout = total_payout.saturating_sub(p);
			if !remaining_payout.is_zero() && pool_record.private_contributions > 0 {
				pool_record.maybe_payout = Some(remaining_payout);
				InstaPoolHistory::<T>::insert(r, &pool_record);
			} else {
				InstaPoolHistory::<T>::remove(r);
			}
```
