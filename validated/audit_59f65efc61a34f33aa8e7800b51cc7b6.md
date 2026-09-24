## Analog Found: Integer‑division truncation in `pallet-asset-rewards` reward accrual

The Ethos `LQTYStaking.increaseF_Collateral` bug (accumulator = `fee * PRECISION / totalStaked` rounding to `0` when `totalStaked` is large relative to the incoming amount) has a direct structural analog in `pallet-asset-rewards`'s `reward_per_token` calculation, which uses a **much weaker precision scaling factor (4096, i.e. 12 bits)** than either the original Solidity contract (`1e18`) or Substrate's own `nomination-pools` pallet (`FixedU128`, `1e18`).

### Title
Reward-per-token calculation permanently truncates to zero and locks reward assets when `total_tokens_staked` is large relative to `reward_rate_per_block` - (File: substrate/frame/asset-rewards/src/lib.rs)

### Summary
`pallet-asset-rewards::reward_per_token` computes `reward_rate_per_block * blocks_elapsed * PRECISION_SCALING_FACTOR / total_tokens_staked` using plain integer division with no remainder tracking. `PRECISION_SCALING_FACTOR` is a constant `4096` [1](#0-0) . Any signed account can permissionlessly call `stake` to inflate `total_tokens_staked` for an existing pool [2](#0-1) . Once `total_tokens_staked` is large enough relative to `reward_rate_per_block * PRECISION_SCALING_FACTOR`, each accrual period contributes `0` to `reward_per_token_stored`, while `last_update_block` is unconditionally advanced, permanently discarding that period's reward share. The corresponding reward asset amount, already sitting in the pool's dedicated account (funded by the admin per the pallet doc's own warning to "keep pool accounts adequately funded") [3](#0-2) , becomes unclaimable and effectively frozen.

### Finding Description
`reward_per_token` is:
```rust
Ok(pool_info.reward_per_token_stored.ensure_add(
    pool_info
        .reward_rate_per_block
        .ensure_mul(rewardable_blocks_elapsed.into())?
        .ensure_mul(PRECISION_SCALING_FACTOR.into())?
        .ensure_div(pool_info.total_tokens_staked)?,
)?)
``` [4](#0-3) 

`ensure_mul`/`ensure_div` only fail on overflow or division-by-zero — they do **not** detect or prevent silent truncation of the fractional remainder to zero. This mirrors the exact math pattern flagged in the Ethos report (`_collFee * DECIMAL_PRECISION / totalLQTYStaked` truncating to `0`), except this pallet's precision constant (`4096`) is astronomically smaller than the `1e18` used both in the original vulnerable contract and in Substrate's own `nomination-pools` pallet, which deliberately uses a `FixedU128` (`1e18`-scaled) `RewardCounter` and documents the accuracy tradeoffs explicitly [5](#0-4) . `pallet-asset-rewards` has no equivalent error-carry/remainder mechanism (unlike the mitigation the original report recommended, which nomination-pools effectively achieves via `FixedU128`).

Because `stake` is a public, permissionless, signed extrinsic that lets any account increase `pool_info.total_tokens_staked` by an arbitrary amount they can source in the staked asset [2](#0-1) , an attacker with no privileged role can deliberately push `total_tokens_staked` past the truncation threshold for a given `reward_rate_per_block`, or normal usage/growth of a popular pool can reach this state organically. Every subsequent call to `update_pool_and_staker_rewards` (triggered from `stake`, `unstake`, and `harvest_rewards`) recomputes `reward_per_token` and unconditionally advances `last_update_block` to the current block [6](#0-5) , so any reward accrued during a truncated-to-zero period is discarded forever — it is not carried forward or recoverable by any staker.

The only pool-level fund-recovery path is `cleanup_pool`, which requires `PoolStakers` for that pool to be fully empty [7](#0-6) , so as long as even one staker remains bonded, the reward asset dust/losses are permanently stuck in the pool account, unreachable by anyone.

### Impact Explanation
Reward tokens already transferred into the pool's dedicated account by the pool admin become permanently unclaimable by any staker whenever `total_tokens_staked` grows large relative to `reward_rate_per_block`. This is a direct, deterministic loss/freezing of legitimately deposited reward funds, reachable purely through the permissionless `stake` extrinsic — no governance, root, or privileged role is required to trigger it, matching the "irreversible freezing" class called out as high-priority impact.

### Likelihood Explanation
Likelihood is proportional to how attractive/large a given pool becomes: any staked asset with meaningful supply/divisibility (e.g., a high-decimal or high-total-supply asset), combined with a modest `reward_rate_per_block`, will hit the truncation threshold. Given `PRECISION_SCALING_FACTOR` is only `4096` (2^12) versus the `1e18` scale used elsewhere in the codebase for equivalent purposes, the threshold is reached far more easily than in comparably-designed pallets, making this a realistic, not merely theoretical, scenario for active pools.

### Recommendation
Increase `PRECISION_SCALING_FACTOR` to a much larger fixed-point scale (e.g. `1e18`/`FixedU128`, mirroring `nomination-pools`'s `RewardCounter` approach), and/or introduce an explicit remainder-carry mechanism analogous to `lastLQTYError` in the original report, so that any reward amount that would otherwise round down to zero for a given accrual period is retained and added into the next period's calculation instead of being silently discarded.

### Proof of Concept
No executable PoC was run against a live network or test harness; this is a source-level identification of the reachable arithmetic truncation path. A concrete integration test would: (1) create a pool with `reward_rate_per_block = R`, (2) have an account call `stake` with a large `amount` to set `total_tokens_staked = N` such that `R * PRECISION_SCALING_FACTOR * blocks_elapsed < N`, (3) advance blocks and call `harvest_rewards`, and (4) assert `staker_info.rewards` remains `0` despite non-zero elapsed reward-rate accrual, using the existing `substrate/frame/asset-rewards/src/tests.rs` and `mock.rs` harness. This was not executed in this analysis; findings are based on direct code inspection of `substrate/frame/asset-rewards/src/lib.rs` lines 117-118, 472-502, 775-810.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L35-38)
```rust
//! Reward assets pending distribution are held in an account unique to each pool.
//!
//! Care should be taken by the pool operator to keep pool accounts adequately funded with the
//! reward asset.
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L117-118)
```rust
/// Multiplier to maintain precision when calculating rewards.
pub(crate) const PRECISION_SCALING_FACTOR: u16 = 4096;
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L472-502)
```rust
		#[pallet::call_index(1)]
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L697-729)
```rust
		pub fn cleanup_pool(origin: OriginFor<T>, pool_id: PoolId) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			ensure!(pool_info.admin == who, BadOrigin);

			let stakers = PoolStakers::<T>::iter_key_prefix(pool_id).next();
			ensure!(stakers.is_none(), Error::<T>::NonEmptyPool);

			let pool_balance = T::Assets::reducible_balance(
				pool_info.reward_asset_id.clone(),
				&pool_info.account,
				Preservation::Expendable,
				Fortitude::Polite,
			);
			T::Assets::transfer(
				pool_info.reward_asset_id,
				&pool_info.account,
				&pool_info.admin,
				pool_balance,
				Preservation::Expendable,
			)?;

			if let Some((who, cost)) = PoolCost::<T>::take(pool_id) {
				T::Consideration::drop(cost, &who)?;
			}

			Pools::<T>::remove(pool_id);

			Self::deposit_event(Event::PoolCleanedUp { pool_id });

			Ok(())
		}
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L775-784)
```rust
		pub fn update_pool_rewards(
			pool_info: &PoolInfoFor<T>,
			reward_per_token: T::Balance,
		) -> Result<PoolInfoFor<T>, DispatchError> {
			let mut new_pool_info = pool_info.clone();
			new_pool_info.last_update_block = T::BlockNumberProvider::current_block_number();
			new_pool_info.reward_per_token_stored = reward_per_token;

			Ok(new_pool_info)
		}
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L786-810)
```rust
		/// Derives the current reward per token for this pool.
		pub(super) fn reward_per_token(
			pool_info: &PoolInfoFor<T>,
		) -> Result<T::Balance, DispatchError> {
			if pool_info.total_tokens_staked.is_zero() {
				return Ok(pool_info.reward_per_token_stored);
			}

			let rewardable_blocks_elapsed: u32 =
				match Self::last_block_reward_applicable(pool_info.expiry_block)
					.ensure_sub(pool_info.last_update_block)?
					.try_into()
				{
					Ok(b) => b,
					Err(_) => return Err(Error::<T>::BlockNumberConversionError.into()),
				};

			Ok(pool_info.reward_per_token_stored.ensure_add(
				pool_info
					.reward_rate_per_block
					.ensure_mul(rewardable_blocks_elapsed.into())?
					.ensure_mul(PRECISION_SCALING_FACTOR.into())?
					.ensure_div(pool_info.total_tokens_staked)?,
			)?)
		}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L1472-1509)
```rust
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
```
