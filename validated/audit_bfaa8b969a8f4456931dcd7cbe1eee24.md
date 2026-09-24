### Title
Permissionless `pallet-asset-rewards` pool admin can set an unbounded `reward_rate_per_block` that overflows and permanently freezes stakers' funds - (File: `substrate/frame/asset-rewards/src/lib.rs`)

### Summary
The external report's root cause is unbounded, unvalidated numeric parameters (`boosterMultiplier`, `pointsPerBlock`) that a controller could set to values large enough to overflow downstream arithmetic, bricking pools and blocking withdrawals. The Polkadot SDK analog is `pallet_asset_rewards`'s `reward_rate_per_block`, which any signed account can set to an unbounded value when creating a pool, or later increase without an upper bound, causing the pool's reward accounting to overflow and permanently reverting `stake`, `unstake`, and `harvest_rewards` for that pool - trapping any staker's frozen tokens.

### Finding Description
`create_pool` accepts an attacker-chosen `reward_rate_per_block: T::Balance` with no upper-bound validation, only asset-existence and expiry checks: [1](#0-0) 

Pool creation is fully permissionless in every runtime that wires this pallet (asset-hub-rococo, asset-hub-westend, the staking-async parachain runtime, and the reference node runtime all use `type CreatePoolOrigin = EnsureSigned<AccountId>`): [2](#0-1) [3](#0-2) 

`create_pool` also auto-assigns the creator as pool `admin` if none is supplied, meaning the caller who chose the malicious rate also controls `set_pool_reward_rate_per_block`, which enforces only monotonic increase, never an upper bound: [4](#0-3) 

The rate is later used in `reward_per_token`, which chains three checked-arithmetic operations (`ensure_mul`/`ensure_div`) over `reward_rate_per_block`, elapsed blocks, and `PRECISION_SCALING_FACTOR`: [5](#0-4) 

Because these use `ensure_*` (checked arithmetic that returns `DispatchError` on overflow rather than panicking or wrapping), a sufficiently large `reward_rate_per_block` combined with even a modest number of elapsed blocks makes `ensure_mul` return an `Arithmetic` error. This propagates through `update_pool_rewards` -> `update_pool_and_staker_rewards`, which is the mandatory first step of `stake`, `unstake`, and `harvest_rewards`: [6](#0-5) [7](#0-6) [8](#0-7) 

Critically, `unstake` calls `Self::update_pool_and_staker_rewards` *before* it unfreezes any tokens, so once the reward computation starts overflowing there is no code path in the pallet that lets a staker retrieve their `T::AssetsFreezer`-frozen tokens from that pool - the freeze becomes permanent for as long as the pool exists (and the overflow only gets worse as more blocks elapse, so it can never self-heal).

### Impact Explanation
Any unprivileged, signed account can create a pool with an extreme `reward_rate_per_block`, let a victim stake real assets into it (e.g., via advertising an attractive reward pool), and once at least one block has elapsed after any nonzero `total_tokens_staked`, every subsequent `stake`, `unstake`, and `harvest_rewards` call for that pool deterministically fails with an arithmetic overflow `DispatchError`. Victim funds placed under `T::AssetsFreezer` for that pool become irrecoverable through any pallet-exposed extrinsic - this is an irreversible freezing/loss-of-funds condition matching the original report's "may break pools indefinitely... causing subsequent accounting to overflow," but manifesting here as permanent denial of withdrawal rather than incorrect issuance (checked arithmetic prevents silent wraparound/theft, but does not prevent the DoS/freeze).

### Likelihood Explanation
High reachability: pool creation and reward-rate setting are both permissionless (`EnsureSigned<AccountId>`), require no governance or privileged role, and only need a single signed extrinsic plus a victim choosing to stake. No malicious validator/collator/relayer or forged inherent is required - this is a standard user-to-user griefing/self-inflicted-freeze vector reachable purely through documented calls (`create_pool`, `stake`, `unstake`).

### Recommendation
Add an explicit, reasonable upper bound (and/or a max total accumulated reward check) on `reward_rate_per_block` at both `create_pool` and `set_pool_reward_rate_per_block`, analogous to the `SophonFarming.sol` fix that capped `pointsPerBlock`/`boosterMultiplier`. Additionally, consider adding a pallet-level "force recover"/admin-independent unstake path that does not depend on `update_pool_and_staker_rewards` succeeding, so a staker's frozen assets are never permanently unreachable due to a corrupted pool's reward math.

### Proof of Concept
No executable PoC was run; this is a static code-path trace based on reading `substrate/frame/asset-rewards/src/lib.rs` and the runtime configs cited above. The failed-guard chain identified is: `create_pool` (no upper bound on `reward_rate_per_block`, line 449-467) -> `set_pool_reward_rate_per_block` (only checks `new > old`, line 900-922) -> `reward_per_token`'s `ensure_mul` chain (line 786-810) -> propagated failure into `stake`/`unstake`/`harvest_rewards`'s call to `update_pool_and_staker_rewards` (lines 472-531, 568-586). I could not locate the exact numeric value of `PRECISION_SCALING_FACTOR` within the available index (only 3 textual matches were found, all in `lib.rs`, but the constant's definition line was not retrieved before the tool budget was exhausted), so the precise minimum `reward_rate_per_block` and block-elapsed threshold needed to trigger the overflow is not confirmed numerically - a background Devin session with full file/terminal access would be needed to build and run a concrete `#[test]` in `substrate/frame/asset-rewards/src/tests.rs` (using `new_test_ext()`, `create_pool`, `stake`, block advance, then `unstake`) to empirically confirm the overflow and resulting `DispatchError`/permanent freeze, and to check whether this pallet is actually deployed/live for a bounty-eligible Parity/Snowbridge program at the affected version.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L449-467)
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
			Ok(())
		}
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L513-531)
```rust
		#[pallet::call_index(2)]
		pub fn unstake(
			origin: OriginFor<T>,
			pool_id: PoolId,
			amount: T::Balance,
			staker: Option<T::AccountId>,
		) -> DispatchResult {
			let caller = ensure_signed(origin)?;
			let staker = staker.unwrap_or(caller.clone());

			// Always start by updating the pool rewards.
			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			let now = T::BlockNumberProvider::current_block_number();
			ensure!(now > pool_info.expiry_block || caller == staker, BadOrigin);

			let staker_info = PoolStakers::<T>::get(pool_id, &staker).unwrap_or_default();
			let (mut pool_info, mut staker_info) =
				Self::update_pool_and_staker_rewards(&pool_info, &staker_info)?;

```

**File:** substrate/frame/asset-rewards/src/lib.rs (L568-586)
```rust
		#[pallet::call_index(3)]
		pub fn harvest_rewards(
			origin: OriginFor<T>,
			pool_id: PoolId,
			staker: Option<T::AccountId>,
		) -> DispatchResult {
			let caller = ensure_signed(origin)?;
			let staker = staker.unwrap_or(caller.clone());

			// Always start by updating the pool and staker rewards.
			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			let now = T::BlockNumberProvider::current_block_number();
			ensure!(now > pool_info.expiry_block || caller == staker, BadOrigin);

			let staker_info =
				PoolStakers::<T>::get(pool_id, &staker).ok_or(Error::<T>::NonExistentStaker)?;
			let (pool_info, mut staker_info) =
				Self::update_pool_and_staker_rewards(&pool_info, &staker_info)?;

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

**File:** cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs (L1062-1081)
```rust
impl pallet_asset_rewards::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type PalletId = AssetRewardsPalletId;
	type Balance = Balance;
	type Assets = NativeAndAllAssets;
	type AssetsFreezer = NativeAndAllAssetsFreezer;
	type AssetId = xcm::v5::Location;
	type CreatePoolOrigin = EnsureSigned<AccountId>;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type Consideration = HoldConsideration<
		AccountId,
		Balances,
		RewardsPoolCreationHoldReason,
		ConstantStoragePrice<StakePoolCreationDeposit, Balance>,
	>;
	type WeightInfo = weights::pallet_asset_rewards::WeightInfo<Runtime>;
	type BlockNumberProvider = frame_system::Pallet<Runtime>;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = PalletAssetRewardsBenchmarkHelper;
}
```

**File:** substrate/bin/node/runtime/src/lib.rs (L2044-2063)
```rust
impl pallet_asset_rewards::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type AssetId = NativeOrWithId<u32>;
	type Balance = Balance;
	type Assets = NativeAndAssets;
	type PalletId = StakingRewardsPalletId;
	type CreatePoolOrigin = EnsureSigned<AccountId>;
	type WeightInfo = ();
	type AssetsFreezer = NativeAndAssetsFreezer;
	type Consideration = HoldConsideration<
		AccountId,
		Balances,
		CreationHoldReason,
		ConstantStoragePrice<StakePoolCreationDeposit, Balance>,
	>;
	type BlockNumberProvider = frame_system::Pallet<Runtime>;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = AssetRewardsBenchmarkHelper;
}
```
