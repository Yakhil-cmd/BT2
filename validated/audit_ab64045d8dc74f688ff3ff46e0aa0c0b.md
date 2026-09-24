### Title
`pallet-asset-rewards`: fixed `PRECISION_SCALING_FACTOR` (4096) causes `reward_per_token` to truncate to zero, permanently freezing reward accrual for a pool - ([File: substrate/frame/asset-rewards/src/lib.rs])

### Summary
`pallet-asset-rewards` computes the per-token reward increment using a fixed, non-configurable scaling constant `PRECISION_SCALING_FACTOR = 4096` [1](#0-0) . Because the scaling factor is a small constant unrelated to the decimals/magnitude of the staked or reward asset, `reward_per_token()` performs an integer division that can truncate to `0` whenever `total_tokens_staked` is large relative to `reward_rate_per_block * elapsed_blocks * 4096`. This is the same root cause described in the external report (raw reward-rate arithmetic lacking sufficient precision multiplier for real-world token magnitudes/decimals), just manifesting in FRAME's `reward_per_token`/`derive_rewards` math instead of an EVM `rewardsPerSecond` field.

### Finding Description
`reward_per_token` is:
```rust
pool_info.reward_per_token_stored.ensure_add(
    pool_info
        .reward_rate_per_block
        .ensure_mul(rewardable_blocks_elapsed.into())?
        .ensure_mul(PRECISION_SCALING_FACTOR.into())?
        .ensure_div(pool_info.total_tokens_staked)?,
)?
``` [2](#0-1) 

`derive_rewards` then divides back by the same `PRECISION_SCALING_FACTOR` to get a staker's owed balance:
```rust
staker_info.amount
    .ensure_mul(reward_per_token.ensure_sub(staker_info.reward_per_token_paid)?)?
    .ensure_div(PRECISION_SCALING_FACTOR.into())?
    .ensure_add(staker_info.rewards)?
``` [3](#0-2) 

`PRECISION_SCALING_FACTOR` is a hard-coded `u16 = 4096` [1](#0-0) . Any signed account can permissionlessly call `stake()` to grow `total_tokens_staked` for a pool it did not create [4](#0-3) , and `create_pool`/`set_pool_reward_rate_per_block` never validate that `reward_rate_per_block * PRECISION_SCALING_FACTOR` remains meaningfully larger than plausible `total_tokens_staked` [5](#0-4) .

Once `reward_rate_per_block.ensure_mul(elapsed).ensure_mul(4096) < total_tokens_staked`, the numerator's integer division by `total_tokens_staked` yields `0`, so `reward_per_token_stored` does not advance for that period — the accrued reward for the elapsed blocks is silently and permanently lost (not merely deferred, since `last_update_block` is advanced regardless). Because staking assets can be arbitrary fungible assets with 18 decimals (or more) via `T::Assets: fungibles::Inspect/Mutate`, and reward rates are set by pool admins in the reward asset's raw units without any decimals-aware scaling, this is directly analogous to the reported class of bug: a fixed, too-small precision multiplier applied without regard to the actual magnitude/decimals of the tokens involved.

Unlike the EVM finding (where rewards are merely "too large" to be practically funded), the FRAME analog is worse: it causes *complete truncation to zero*, i.e. reward accrual silently stops, and any staker (not just the pool admin) can trigger it by staking a sufficiently large amount of the staking asset, since `stake()` is open to any signed account and there is no minimum-precision safety check anywhere in the call path.

### Impact Explanation
This is a Medium-severity integrity/availability issue on the incentive mechanism of `pallet-asset-rewards`, which is wired into production Asset Hub runtimes (`asset-hub-westend`, `asset-hub-rococo`) [6](#0-5) . Impact:
- Reward accrual can be pushed to zero for arbitrarily long periods, permanently freezing rewards owed to all other stakers in the pool for those blocks (rewards are not "delayed," they are lost since `reward_per_token_stored`/`last_update_block` are unconditionally advanced).
- No privileged role, governance action, or malicious validator/collator is required — a normal user with sufficient balance of the staked asset can grief any pool by staking a large amount temporarily to depress `total_tokens_staked` versus the fixed 4096 scaling factor.
- This does not directly mint or steal funds, so it does not rise to Critical/High theft or unbacked issuance, but it is a real, demonstrable integrity break of the reward-distribution invariant that the report describes ("rewardsPerSecond is not accurate enough").

### Likelihood Explanation
Likelihood is Medium: it requires the attacker (or even an honest large staker) to hold/stake an amount of the staking asset large enough relative to `reward_rate_per_block * 4096 * elapsed_blocks`. For any staking asset with realistic decimals (e.g., 18) and a pool admin setting a reward rate in "natural" units (as in the WBTC/EURS example from the source report), this condition is trivially reachable, since `PRECISION_SCALING_FACTOR` is a flat `4096` regardless of asset decimals.

### Recommendation
- Replace the fixed `PRECISION_SCALING_FACTOR: u16 = 4096` with a much larger, ideally per-asset-decimals-aware precision multiplier (e.g., `10^18` fixed-point, as done in `pallet-nomination-pools`'s `RewardCounter: FixedPointNumber`) [7](#0-6) .
- Add a validation in `create_pool`/`set_pool_reward_rate_per_block` that rejects reward-rate/staked-asset configurations where `reward_rate_per_block * PRECISION_SCALING_FACTOR` could plausibly be dominated by `total_tokens_staked`, or use checked arithmetic that detects and errors on truncation to zero (rather than silently losing the accrued amount and advancing `last_update_block`).
- Consider accumulating a remainder/dust carry-over across updates so that partial-period rewards are not discarded when the division truncates.

### Proof of Concept
Deployment evidence: `pallet-asset-rewards` is included in `asset-hub-westend`/`asset-hub-rococo` runtimes and has dedicated weights, confirming it is production code, not test/mock-only [8](#0-7) .

Failed guard: `create_pool` performs no check relating `reward_rate_per_block`, `PRECISION_SCALING_FACTOR`, and expected `total_tokens_staked` magnitude [9](#0-8) ; `stake()` is unrestricted to any signed account.

Minimal reproduction sketch (arithmetic, not executed against a live network per instructions):
1. Admin creates a pool with `reward_rate_per_block = 100` (reward asset raw units) and an 18-decimal staking asset.
2. A staker calls `stake()` with `amount = 10^24` raw units (a realistic 18-decimal-token balance, e.g. ~1,000,000 tokens).
3. After `N` blocks, `reward_per_token()` numerator = `100 * N * 4096`. For `N` up to ~2.4 million blocks (multiple months), `100 * N * 4096 < 10^24`, so `ensure_div` truncates to `0`, and `reward_per_token_stored` never increases despite the pool admin having funded rewards and blocks having elapsed.
4. `last_update_block` is still advanced in `update_pool_rewards`, so this reward period is unrecoverable — the tests in `substrate/frame/asset-rewards/src/tests.rs` (e.g. `staker_rewards_are_affected_correctly`, `integration`) only exercise small, "nice" balances (100s–1000s) and never validate behavior at realistic decimal/token magnitudes, so this precision-loss scenario is not covered by the existing test suite [10](#0-9) .

Execution status: this is a code-level arithmetic derivation from the cited production formulas; no test harness run was performed as part of this analysis (no PoC execution claimed).

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L117-118)
```rust
/// Multiplier to maintain precision when calculating rewards.
pub(crate) const PRECISION_SCALING_FACTOR: u16 = 4096;
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L803-809)
```rust
			Ok(pool_info.reward_per_token_stored.ensure_add(
				pool_info
					.reward_rate_per_block
					.ensure_mul(rewardable_blocks_elapsed.into())?
					.ensure_mul(PRECISION_SCALING_FACTOR.into())?
					.ensure_div(pool_info.total_tokens_staked)?,
			)?)
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L815-824)
```rust
		fn derive_rewards(
			staker_info: &PoolStakerInfo<T::Balance>,
			reward_per_token: &T::Balance,
		) -> Result<T::Balance, DispatchError> {
			Ok(staker_info
				.amount
				.ensure_mul(reward_per_token.ensure_sub(staker_info.reward_per_token_paid)?)?
				.ensure_div(PRECISION_SCALING_FACTOR.into())?
				.ensure_add(staker_info.rewards)?)
		}
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L837-898)
```rust
impl<T: Config> RewardsPool<T::AccountId> for Pallet<T> {
	type AssetId = T::AssetId;
	type BlockNumber = BlockNumberFor<T>;
	type PoolId = PoolId;
	type Balance = T::Balance;

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

		// Emit created event.
		Self::deposit_event(Event::PoolCreated {
			creator: creator.clone(),
			pool_id,
			staked_asset_id,
			reward_asset_id,
			reward_rate_per_block,
			expiry_block,
			admin: admin.clone(),
		});

		Ok(pool_id)
	}
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L900-922)
```rust
	fn set_pool_reward_rate_per_block(
		admin: &T::AccountId,
		pool_id: PoolId,
		new_reward_rate_per_block: T::Balance,
	) -> DispatchResult {
		let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
		ensure!(pool_info.admin == *admin, BadOrigin);
		ensure!(
			new_reward_rate_per_block > pool_info.reward_rate_per_block,
			Error::<T>::RewardRateCut
		);

		// Always start by updating the pool rewards.
		let rewards_per_token = Self::reward_per_token(&pool_info)?;
		let mut pool_info = Self::update_pool_rewards(&pool_info, rewards_per_token)?;

		pool_info.reward_rate_per_block = new_reward_rate_per_block;
		Pools::<T>::insert(pool_id, pool_info);

		Self::deposit_event(Event::PoolRewardRateModified { pool_id, new_reward_rate_per_block });

		Ok(())
	}
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L1-1)
```rust
// Copyright (C) Parity Technologies (UK) Ltd.
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L1674-1686)
```rust
		/// The type that is used for reward counter.
		///
		/// The arithmetic of the reward counter might saturate based on the size of the
		/// `Currency::Balance`. If this happens, operations fails. Nonetheless, this type should be
		/// chosen such that this failure almost never happens, as if it happens, the pool basically
		/// needs to be dismantled (or all pools migrated to a larger `RewardCounter` type, which is
		/// a PITA to do).
		///
		/// See the inline code docs of `Member::pending_rewards` and `RewardPool::update_recorded`
		/// for example analysis. A [`sp_runtime::FixedU128`] should be fine for chains with balance
		/// types similar to that of Polkadot and Kusama, in the absence of severe slashing (or
		/// prevented via a reasonable `MaxPointsToBalance`), for many many years to come.
		type RewardCounter: FixedPointNumber + MaxEncodedLen + TypeInfo + Default + codec::FullCodec;
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/weights/pallet_asset_rewards.rs (L1-1)
```rust
// Copyright (C) Parity Technologies (UK) Ltd.
```

**File:** substrate/frame/asset-rewards/src/tests.rs (L1063-1094)
```rust
	#[test]
	fn staker_rewards_are_affected_correctly() {
		new_test_ext().execute_with(|| {
			let admin = 1;
			let staker = 2;
			let pool_id = 0;
			let new_reward_rate = 150;
			create_default_pool();

			// Stake some tokens, and accumulate 10 blocks of rewards at the default pool rate (100)
			System::set_block_number(10);
			assert_ok!(StakingRewards::stake(RuntimeOrigin::signed(staker), pool_id, 1000));
			System::set_block_number(20);

			// Increase the reward rate
			assert_ok!(StakingRewards::set_pool_reward_rate_per_block(
				RuntimeOrigin::signed(admin),
				pool_id,
				new_reward_rate
			));

			// Accumulate 10 blocks of rewards at the new rate
			System::set_block_number(30);

			// Check that rewards are calculated correctly with the updated rate
			assert_hypothetically_earned(
				staker,
				10 * 100 + 10 * new_reward_rate,
				pool_id,
				NativeOrWithId::<u32>::Native,
			);
		});
```
