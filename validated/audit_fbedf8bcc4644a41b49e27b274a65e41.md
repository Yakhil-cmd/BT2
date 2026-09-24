### Title
Zero/near-zero reward accrual via permissionless zero-amount `stake` griefing due to precision loss in `reward_per_token` - (File: substrate/frame/asset-rewards/src/lib.rs)

### Summary
`pallet-asset-rewards` (a FRAME re-implementation of Synthetix's `StakingRewards.sol`/MultiRewards pattern) computes `reward_per_token_stored` with an integer division scaled only by `PRECISION_SCALING_FACTOR = 4096`, far smaller than the `1e18` scaling used in the original Solidity contract that the referenced report analyzes. Any signed account can permissionlessly call the `stake` extrinsic with `amount = 0`, which still executes `update_pool_and_staker_rewards` and commits a new `last_update_block` to storage. When `rewardable_blocks_elapsed * reward_rate_per_block * 4096 < total_tokens_staked`, `reward_per_token_stored` does not increase even though `last_update_block` advances, permanently erasing rewards accrued for that time window for every staker in the pool — the exact griefing pattern described in the external report, reachable here with a much lower bar due to the small scaling factor.

### Finding Description
`Pallet::<T>::reward_per_token` computes:
```rust
Ok(pool_info.reward_per_token_stored.ensure_add(
    pool_info.reward_rate_per_block
        .ensure_mul(rewardable_blocks_elapsed.into())?
        .ensure_mul(PRECISION_SCALING_FACTOR.into())?   // PRECISION_SCALING_FACTOR = 4096
        .ensure_div(pool_info.total_tokens_staked)?,
)?)
``` [1](#0-0) 

`PRECISION_SCALING_FACTOR` is fixed at `4096` [2](#0-1) , which is dramatically smaller than the `1e18` scaling factor Synthetix uses. Whenever `rewardable_blocks_elapsed * reward_rate_per_block * 4096 < total_tokens_staked`, integer division truncates the increment to zero, so `reward_per_token_stored` stays unchanged.

Every write path that calls `update_pool_and_staker_rewards`/`update_pool_rewards` unconditionally advances `last_update_block` to the current block via `update_pool_rewards`:
```rust
pub fn update_pool_rewards(...) -> Result<PoolInfoFor<T>, DispatchError> {
    let mut new_pool_info = pool_info.clone();
    new_pool_info.last_update_block = T::BlockNumberProvider::current_block_number();
    new_pool_info.reward_per_token_stored = reward_per_token;
    Ok(new_pool_info)
}
``` [3](#0-2) 

Because `lastUpdateTime`/`last_update_block` still advances while `reward_per_token_stored` does not, the reward accrued during that elapsed window is permanently lost for every staker of the pool — identical to the "griefing" edge case described in the external report for `MultiRewards.sol`.

The critical entry point is the `stake` extrinsic, which is a real, permissionless, signed extrinsic with no privileged-role requirement and, crucially, has no minimum-amount check:
```rust
pub fn stake(origin: OriginFor<T>, pool_id: PoolId, amount: T::Balance) -> DispatchResult {
    let staker = ensure_signed(origin)?;
    let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
    let staker_info = PoolStakers::<T>::get(pool_id, &staker).unwrap_or_default();
    let (mut pool_info, mut staker_info) =
        Self::update_pool_and_staker_rewards(&pool_info, &staker_info)?;
    T::AssetsFreezer::increase_frozen(..., amount)?;
    pool_info.total_tokens_staked.ensure_add_assign(amount)?;
    Pools::<T>::insert(pool_id, pool_info);
    ...
}
``` [4](#0-3) 

There is no `ensure!(amount > 0, ...)` guard anywhere in `stake` (verified by reading the full function body and grepping for zero-amount checks in the pallet), so calling `stake(pool_id, 0)` is a fully valid, zero-cost-beyond-fee, no-privilege operation that any account can call every block to force `update_pool_and_staker_rewards` → `update_pool_rewards` and advance `last_update_block` while the attacker fully controls `dt` (the number of blocks elapsed, as low as 1). `unstake` and `harvest_rewards` also invoke the same update path but are gated to the staker themselves (or anyone after pool expiry) [5](#0-4) ; `stake` with zero amount, however, is unrestricted for any signer and any existing pool.

This mirrors the report's violated invariant exactly: "the residual amount `(dt * rate * scale) % totalSupply` is unutilized" and "attacker-controlled `dt` via a permissionlessly-invokable update path can zero out rewards for the whole duration." The Rust analog is arguably a stronger instance of the bug class because the scaling factor (4096) is ~2.4×10^14 times smaller than Solidity's `1e18`, making the zero-accrual condition trivially satisfiable for realistic pool sizes (e.g. any pool with `total_tokens_staked` on the order of `10^6` or higher relative to `reward_rate_per_block`, which is common for assets with 12–18 decimals).

### Impact Explanation
Medium. Continuous invocation of `stake(pool_id, 0)` by any unprivileged account causes: (a) a continuous build-up of unclaimable/stuck reward-asset dust in the pool account due to routine precision loss, and (b) under the demonstrated condition, complete loss of reward accrual for the duration between the attacker's calls, for every staker in the affected pool, without requiring governance, keys, or any privileged role. This is directly analogous to the "Medium" impact rated in the source report for `MultiRewards.sol`.

### Likelihood Explanation
Medium-to-High. No privileged role, stolen key, or malicious infrastructure is required — only a signed account and normal transaction fees for the `stake` extrinsic with `amount = 0`. Because `PRECISION_SCALING_FACTOR` is only `4096` (vs `1e18` in the referenced Solidity contract), the zero-accrual condition (`rewardable_blocks_elapsed * reward_rate_per_block * 4096 < total_tokens_staked`) is satisfied for a much wider range of realistic pool configurations than in the original report, making exploitation easier here, not harder.

### Recommendation
- Track and carry forward the truncated remainder of `reward_rate_per_block * rewardable_blocks_elapsed * PRECISION_SCALING_FACTOR % total_tokens_staked` across invocations (e.g. store a `reward_remainder` field in `PoolInfo` and add it back in before the next division) so precision loss cannot accumulate or be repeatedly triggered to zero.
- Add a minimum non-zero `amount` check (`ensure!(!amount.is_zero(), Error::<T>::...)`) to the `stake` extrinsic (and consider rate-limiting/weight-based deterrents for reward-update-only calls) to remove the free, permissionless lever that lets any account force `last_update_block` to advance without contributing meaningfully to `total_tokens_staked`.
- Consider increasing `PRECISION_SCALING_FACTOR` substantially (or switching to a fixed-point/`FixedU128`-based reward-counter approach as used in `pallet-nomination-pools`'s `current_reward_counter`, which is far less susceptible to this truncation-to-zero failure mode) [6](#0-5) .

### Proof of Concept
No executable PoC was run against a live network or existing test harness in this analysis; the following describes a deterministic Rust/FRAME unit-test reproduction path using the pallet's own mock runtime (`substrate/frame/asset-rewards/src/mock.rs`, `MockRuntime`) that a maintainer can execute to confirm the finding:

1. Using `new_test_ext()` from `substrate/frame/asset-rewards/src/mock.rs` [7](#0-6) , create a pool via `create_pool` with a `reward_rate_per_block` and a `staked_asset_id`, then have a legitimate staker call `stake(pool_id, total_tokens_staked)` such that `reward_rate_per_block * PRECISION_SCALING_FACTOR (4096) < total_tokens_staked` (e.g. `reward_rate_per_block = 1`, `total_tokens_staked = 10_000`).
2. From an unrelated, unprivileged account (e.g. account `2`), repeatedly call `stake(pool_id, 0)` once per block, advancing `System::set_block_number` by 1 between calls, for the duration the legitimate staker expects to accrue rewards.
3. After each call, read `Pools::<MockRuntime>::get(pool_id).reward_per_token_stored` and `.last_update_block` — expected/actual assertion: `last_update_block` equals the current block (advances every call) while `reward_per_token_stored` remains unchanged (per `reward_per_token` in `lib.rs` lines 786-810 [8](#0-7) ), demonstrating the legitimate staker's `earned`/`derive_rewards` output stays at zero despite reward-eligible time elapsing.
4. This reproduction was not executed in this session; it is provided as a concrete, minimal integration-test path through the pallet's real `stake` extrinsic boundary for a maintainer or background agent to run and confirm the state transition described above.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L117-118)
```rust
/// Multiplier to maintain precision when calculating rewards.
pub(crate) const PRECISION_SCALING_FACTOR: u16 = 4096;
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L513-530)
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

**File:** substrate/frame/nomination-pools/src/lib.rs (L1506-1509)
```rust
		let current_reward_counter =
			T::RewardCounter::checked_from_rational(new_pending_rewards, bonded_points)
				.and_then(|ref r| self.last_recorded_reward_counter.checked_add(r))
				.ok_or(Error::<T>::OverflowRisk)?;
```

**File:** substrate/frame/asset-rewards/src/mock.rs (L177-227)
```rust
pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<MockRuntime>::default().build_storage().unwrap();

	pallet_assets::GenesisConfig::<MockRuntime, Instance1> {
		// Genesis assets: id, owner, is_sufficient, min_balance
		// pub assets: Vec<(T::AssetId, T::AccountId, bool, T::Balance)>,
		assets: vec![(1, 1, true, 1), (10, 1, true, 1), (20, 1, true, 1)],
		// Genesis metadata: id, name, symbol, decimals
		// pub metadata: Vec<(T::AssetId, Vec<u8>, Vec<u8>, u8)>,
		metadata: vec![
			(1, b"test".to_vec(), b"TST".to_vec(), 18),
			(10, b"test10".to_vec(), b"T10".to_vec(), 18),
			(20, b"test20".to_vec(), b"T20".to_vec(), 18),
		],
		// Genesis accounts: id, account_id, balance
		// pub accounts: Vec<(T::AssetId, T::AccountId, T::Balance)>,
		accounts: vec![
			(1, 1, 10000),
			(1, 2, 20000),
			(1, 3, 30000),
			(1, 4, 40000),
			(1, 10, 40000),
			(1, 20, 40000),
		],
		next_asset_id: None,
		reserves: vec![],
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let pool_zero_account_id = 31086825966906540362769395565;
	pallet_balances::GenesisConfig::<MockRuntime> {
		balances: vec![
			(0, 10000),
			(1, 10000),
			(2, 20000),
			(3, 30000),
			(4, 40000),
			(10, 40000),
			(20, 40000),
			(pool_zero_account_id, 100_000), // Top up the default pool account id
		],
		..Default::default()
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}
```
