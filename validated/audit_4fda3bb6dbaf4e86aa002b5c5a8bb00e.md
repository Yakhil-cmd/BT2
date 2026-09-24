### Title
Reward tokens accrued while a pool has zero staked tokens become permanently unclaimable once staking resumes - ([File: substrate/frame/asset-rewards/src/lib.rs])

### Summary
`pallet-asset-rewards` implements a Synthetix-`StakingRewards.sol`-style reward algorithm (explicitly documented as such in the pallet docs) [1](#0-0) . Like the Tokemak `AbstractRewarder`, its reward rate is fixed per pool over a fixed `expiry_block` window, independent of whether anyone is actually staked. Any block range in which `total_tokens_staked == 0` silently drops the rewards for that range instead of deferring them, and once a staker exists the pool can no longer be swept clean, so those tokens become stuck.

### Finding Description
When a pool is created via `create_pool`, an admin sets `reward_rate_per_block` and a fixed `expiry_block` [2](#0-1) . Reward accrual is computed lazily in `reward_per_token`:

```
if pool_info.total_tokens_staked.is_zero() {
    return Ok(pool_info.reward_per_token_stored);
}
``` [3](#0-2) 

When total staked is zero, the function returns the stored reward-per-token unchanged (no accrual to any staker, correctly, since there is no staker to attribute it to). However, `update_pool_rewards`, called right after, unconditionally advances `last_update_block` to the current block regardless of whether stake was zero:

```
new_pool_info.last_update_block = T::BlockNumberProvider::current_block_number();
new_pool_info.reward_per_token_stored = reward_per_token;
``` [4](#0-3) 

Because `expiry_block` is fixed at pool creation (or extension) time and does not move to compensate for zero-stake gaps, the reward budget for any period during which `total_tokens_staked == 0` (e.g., the gap between `create_pool` and the first `stake`, or any period after all stakers `unstake`) is simply never attributed to a staker's `rewards` balance — it is dropped from the accrual formula rather than rolled forward. This mirrors the Tokemak `AbstractRewarder.queueNewRewards`/`notifyRewardAmount` flaw: the reward-per-block rate times the elapsed idle blocks is real reward-asset balance sitting in the pool's `T::Assets` account (`pool_info.account`) that is unassignable to any staker.

The pallet does provide `cleanup_pool`, letting the admin reclaim leftover reward-asset balance from the pool account, but only when there are currently no stakers (`ensure!(stakers.is_none(), Error::<T>::NonEmptyPool)`) [5](#0-4) . Once a staker joins after an idle period, that idle-period's dropped reward balance can never be recovered by anyone — not distributed to stakers (because it was never accrued into `reward_per_token_stored`), and not reclaimable by the admin (because `NonEmptyPool` blocks `cleanup_pool` while any staker remains, which for a long-lived pool is expected to be always/most of the time).

### Impact Explanation
Reward assets deposited into a pool's reward account (via `create_pool` funding or `deposit_reward_tokens`) for periods when `total_tokens_staked == 0` are permanently stranded once a staker exists, since neither the reward-distribution accounting (`reward_per_token`) nor the sweep mechanism (`cleanup_pool`, gated on `NonEmptyPool`) can recover them. This is a fund-freezing/loss issue for the pool admin/creator who funded the pool, matching a Medium severity classification consistent with the original Tokemak finding.

### Likelihood Explanation
This requires no privileged action or attacker input at all — it occurs naturally any time a pool is created and reward-token funding begins accruing (per block) before the first staker joins, or any time all stakers fully unstake before restaking. Given `create_pool` requires `expiry_block > now` [6](#0-5)  but has no requirement that staking start immediately, this is a routine operational scenario, not an edge case requiring adversarial setup.

### Recommendation
Track reward accrual against actual staked-block time rather than wall-clock `expiry_block`, e.g., only start/advance the reward clock once `total_tokens_staked` becomes non-zero (pause `last_update_block` advancement while stake is zero, and correspondingly extend `expiry_block`/effective end time by the idle duration), or alternatively allow the admin to reclaim the idle-period unclaimed reward delta directly (independent of the `NonEmptyPool` check in `cleanup_pool`) by tracking cumulative "dropped" reward-per-block amounts during zero-stake windows.

### Proof of Concept
No executable PoC was run; this is a design-level trace through `reward_per_token` and `update_pool_rewards`/`cleanup_pool` in `substrate/frame/asset-rewards/src/lib.rs`. I could not find any existing test in `substrate/frame/asset-rewards/src/tests.rs` that specifically exercises a "no stake for N blocks, then first stake" scenario to confirm expected/actual reward totals reported by the pallet's own test suite, nor any code comment acknowledging this as intended behavior — this could not be conclusively verified given index limits, and a background Devin session with full repo access would be needed to write and run a concrete integration test (create_pool → wait N blocks with zero stake → first stake → assert dropped rewards) to confirm the exact numeric loss and rule out any compensating mechanism I may have missed.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L65-68)
```rust
//! ## Rewards Algorithm
//!
//! The rewards algorithm is based on the Synthetix [StakingRewards.sol](https://web.archive.org/web/20251223190741/https://github.com/Synthetixio/synthetix/blob/develop/contracts/StakingRewards.sol)
//! smart contract.
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L700-722)
```rust
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L787-810)
```rust
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L843-884)
```rust
	fn create_pool(
		creator: &T::AccountId,
		staked_asset_id: T::AssetId,
		reward_asset_id: T::AssetId,
		reward_rate_per_block: T::Balance,
		expiry: DispatchTime<BlockNumberFor<T>>,
		admin: &T::AccountId,
	) -> Result<PoolId, DispatchError> {
		// Ensure the assets exist.
		ensure!(T::Assets::asset_exists(staked_asset_id.clone()), Error::<T>::NonExistentAsset);
		ensure!(T::Assets::asset_exists(reward_asset_id.clone()), Error::<T>::NonExistentAsset);

		// Check the expiry block.
		let now = T::BlockNumberProvider::current_block_number();
		let expiry_block = expiry.evaluate(now);
		ensure!(expiry_block > now, Error::<T>::ExpiryBlockMustBeInTheFuture);

		let pool_id = NextPoolId::<T>::try_mutate(|id| -> Result<PoolId, DispatchError> {
			let current_id = *id;
			*id = id.ensure_add(1)?;
			Ok(current_id)
		})?;

		let footprint = Self::pool_creation_footprint();
		let cost = T::Consideration::new(creator, footprint)?;
		PoolCost::<T>::insert(pool_id, (creator.clone(), cost));

		// Create the pool.
		let pool = PoolInfoFor::<T> {
			staked_asset_id: staked_asset_id.clone(),
			reward_asset_id: reward_asset_id.clone(),
			reward_rate_per_block,
			total_tokens_staked: 0u32.into(),
			reward_per_token_stored: 0u32.into(),
			last_update_block: 0u32.into(),
			expiry_block,
			admin: admin.clone(),
			account: Self::pool_account_id(&pool_id),
		};

		// Insert it into storage.
		Pools::<T>::insert(pool_id, pool);
```
