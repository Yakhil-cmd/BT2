No vulnerability found for this question.

The `balanceOfYsCvgAt` bug is a Solidity-specific accounting flaw in Convergence's `LockingPositionService.sol`, where a snapshot-balance function fails to check `_extensions[i].endCycle >= _cycleId` before summing, causing cumulative overcounting of expired lock extensions. This code is not part of the polkadot-sdk repository at all.

I searched for structurally analogous "sum of balances across time-bounded periods" patterns in FRAME pallets that manage locks and snapshots — `pallet-vesting`'s `locked_at`/`vesting_balance` and `pallet-conviction-voting`'s `Voting::locked_balance`/`extend_lock`/`update_lock`. Both use correct bounding logic:

- `VestingInfo::locked_at` saturates to zero when the query block precedes the schedule's start, and multiplies remaining blocks by `per_block`, which naturally saturates to zero once the schedule has fully vested — it never sums stale/expired schedules as if still active. [1](#0-0) 
- `vesting_balance` folds `locked_at` over all schedules at the current block, which correctly excludes fully-vested (expired) schedules from contributing nonzero amounts. [2](#0-1) 
- `pallet-conviction-voting`'s lock accounting takes the `max()` of relevant locks rather than summing across historical periods, and `PriorLock` explicitly separates expired vs. active locks via `rejig`, so there is no equivalent "sum across all past cycles regardless of expiry" defect. [3](#0-2) [4](#0-3) 

None of these constitute a demonstrable analog of the reported invariant violation (missing "current cycle < endCycle" check leading to double-counting of expired periods) reachable via a real signed extrinsic with attacker-controlled input in this codebase. Per the constraints of this task, I am not forcing an EVM-specific accounting analogy onto FRAME code without concrete evidence of an equivalent bug.

### Citations

**File:** substrate/frame/vesting/src/vesting_info.rs (L88-101)
```rust
	pub fn locked_at<BlockNumberToBalance: Convert<BlockNumber, Balance>>(
		&self,
		n: BlockNumber,
	) -> Balance {
		// Number of blocks that count toward vesting;
		// saturating to 0 when n < starting_block.
		let vested_block_count = n.saturating_sub(self.starting_block);
		let vested_block_count = BlockNumberToBalance::convert(vested_block_count);
		// Return amount that is still locked in vesting.
		vested_block_count
			.checked_mul(&self.per_block()) // `per_block` accessor guarantees at least 1.
			.map(|to_unlock| self.locked.saturating_sub(to_unlock))
			.unwrap_or(Zero::zero())
	}
```

**File:** substrate/frame/vesting/src/lib.rs (L763-769)
```rust
	fn vesting_balance(who: &T::AccountId) -> Option<BalanceOf<T>> {
		if let Some(v) = Vesting::<T>::get(who) {
			let now = T::BlockNumberProvider::current_block_number();
			let total_locked_now = v.iter().fold(Zero::zero(), |total, schedule| {
				schedule.locked_at::<T::BlockNumberToBalance>(now).saturating_add(total)
			});
			Some(T::Currency::free_balance(who).min(total_locked_now))
```

**File:** substrate/frame/conviction-voting/src/vote.rs (L282-294)
```rust
	pub fn rejig(&mut self, now: BlockNumber) {
		AsMut::<PriorLock<BlockNumber, Balance>>::as_mut(self).rejig(now);
	}

	/// The amount of this account's balance that must currently be locked due to voting.
	pub fn locked_balance(&self) -> Balance {
		match self {
			Voting::Casting(Casting { votes, prior, .. }) => {
				votes.iter().map(|i| i.1.balance()).fold(prior.locked(), |a, i| a.max(i))
			},
			Voting::Delegating(Delegating { balance, prior, .. }) => *balance.max(&prior.locked()),
		}
	}
```

**File:** substrate/frame/conviction-voting/src/lib.rs (L731-761)
```rust
	/// Rejig the lock on an account. It will never get more stringent (since that would indicate
	/// a security hole) but may be reduced from what they are currently.
	fn update_lock(class: &ClassOf<T, I>, who: &T::AccountId) {
		let class_lock_needed = VotingFor::<T, I>::mutate(who, class, |voting| {
			voting.rejig(T::BlockNumberProvider::current_block_number());
			voting.locked_balance()
		});
		let lock_needed = ClassLocksFor::<T, I>::mutate(who, |locks| {
			locks.retain(|x| &x.0 != class);
			if !class_lock_needed.is_zero() {
				let ok = locks.try_push((class.clone(), class_lock_needed)).is_ok();
				debug_assert!(
					ok,
					"Vec bounded by number of classes; \
					all items in Vec associated with a unique class; \
					qed"
				);
			}
			locks.iter().map(|x| x.1).max().unwrap_or(Zero::zero())
		});
		if lock_needed.is_zero() {
			T::Currency::remove_lock(CONVICTION_VOTING_ID, who);
		} else {
			T::Currency::set_lock(
				CONVICTION_VOTING_ID,
				who,
				lock_needed,
				WithdrawReasons::except(WithdrawReasons::RESERVE),
			);
		}
	}
```
