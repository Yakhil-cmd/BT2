No vulnerability found for this question.

Rationale: The Sherlock report's flaw is that `StakingRewardsManager.createNewStakingRewardsContract()` never checks that the reward token differs from the staking token, an implicit assumption violation in that specific EVM contract. Searching for a Polkadot SDK analog turned up `pallet-asset-rewards`, whose `create_pool` extrinsic and `RewardsPool::create_pool` trait explicitly take independent `staked_asset_id` and `reward_asset_id` parameters [1](#0-0) . This is not an oversight — the pallet's own documentation states it is designed to let holders of a "staking asset" earn rewards denominated in a distinct "reward asset" (e.g., staking LP tokens to earn a different reward token) [2](#0-1) . Pool creation is gated by `T::CreatePoolOrigin`, a permissioned origin, not an arbitrary signed extrinsic [3](#0-2) , and both assets are validated to exist before pool creation [4](#0-3) .

There is no missing invariant here comparable to the report: the "staking token == reward token" assumption from the audited Solidity contract simply does not apply to this FRAME pallet's design, and there's no unauthorized/unprivileged entry point that could trigger unintended asset-mismatch behavior — pool creation requires a permissioned origin by design (the report explicitly excludes privileged-role findings). `pallet-nomination-pools`, the other staking-with-rewards pallet in the codebase, uses the same native currency for both bonding and reward payout via `T::Currency`/`T::StakeAdapter`, so no analogous reward/stake token mismatch surface exists there either [5](#0-4) .

Since the underlying behavior in `pallet-asset-rewards` is intentional, documented, and permission-gated (not attacker-reachable without privilege), there is no demonstrable Polkadot SDK analog vulnerability to report.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L18-34)
```rust
//! # FRAME Staking Rewards Pallet
//!
//! Allows accounts to be rewarded for holding `fungible` asset/s, for example LP tokens.
//!
//! ## Overview
//!
//! Initiate an incentive program for a fungible asset by creating a new pool.
//!
//! During pool creation, a 'staking asset', 'reward asset', 'reward rate per block', 'expiry
//! block', and 'admin' are specified.
//!
//! Once created, holders of the 'staking asset' can 'stake' them in a corresponding pool, which
//! creates a Freeze on the asset.
//!
//! Once staked, rewards denominated in 'reward asset' begin accumulating to the staker,
//! proportional to their share of the total staked tokens in the pool.
//!
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L449-465)
```rust
		pub fn create_pool(
			origin: OriginFor<T>,
			staked_asset_id: Box<T::AssetId>,
			reward_asset_id: Box<T::AssetId>,
			reward_rate_per_block: T::Balance,
			expiry: DispatchTime<BlockNumberFor<T>>,
			admin: Option<T::AccountId>,
		) -> DispatchResult {
			let creator = T::CreatePoolOrigin::ensure_origin(origin)?;
			<Self as RewardsPool<_>>::create_pool(
				&creator,
				*staked_asset_id,
				*reward_asset_id,
				reward_rate_per_block,
				expiry,
				&admin.unwrap_or_else(|| creator.clone()),
			)?;
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L851-853)
```rust
		// Ensure the assets exist.
		ensure!(T::Assets::asset_exists(staked_asset_id.clone()), Error::<T>::NonExistentAsset);
		ensure!(T::Assets::asset_exists(reward_asset_id.clone()), Error::<T>::NonExistentAsset);
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3436-3441)
```rust
	/// Create the reward account of a pool with the given id.
	pub fn generate_reward_account(id: PoolId) -> T::AccountId {
		// NOTE: in order to have a distinction in the test account id type (u128), we put
		// account_type first so it does not get truncated out.
		T::PalletId::get().into_sub_account_truncating((AccountType::Reward, id))
	}
```
