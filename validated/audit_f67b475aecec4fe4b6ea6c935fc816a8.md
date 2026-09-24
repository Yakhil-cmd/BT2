### Title
Reward pool becomes permanently unusable after expiry due to `last_update_block` underflow in `reward_per_token()` - (File: `substrate/frame/asset-rewards/src/lib.rs`)

### Summary
The `pallet-asset-rewards` (FRAME analog of the Synthetix `StakingRewards.sol`-style contract referenced in the report, see the pallet's own doc comment citing it as the algorithm basis [1](#0-0) ) has the same class of bug as the reported `_rewardPerToken()` underflow. `update_pool_rewards()` records `last_update_block` as the *actual* current block instead of capping it at `expiry_block`, while `reward_per_token()` subtracts `last_update_block` from the capped `last_block_reward_applicable(expiry_block)`. Once any account interacts with the pool after expiry, `last_update_block` exceeds `expiry_block`, and every subsequent call for that pool (by any account) underflows and reverts, permanently bricking `stake`, `unstake`, `harvest_rewards`, `set_pool_reward_rate_per_block`, and `set_pool_expiry_block` for that pool.

### Finding Description
`reward_per_token()` computes elapsed blocks as: [2](#0-1) 

where `last_block_reward_applicable` caps at `expiry_block`: [3](#0-2) 

However, `update_pool_rewards()`, which persists `last_update_block` after every successful interaction, does **not** cap it — it always stores the true current block number: [4](#0-3) 

Sequence:
1. Pool expires at block `E`. Some staker calls `stake`, `unstake`, or `harvest_rewards` at block `N > E` while `last_update_block <= E` (still valid from before expiry). `reward_per_token()` computes `E - last_update_block` successfully (no underflow), and `update_pool_rewards()` then sets `last_update_block = N` (uncapped, `N > E`).
2. Any further call touching this pool — by the same or a different staker — at block `M >= N > E` invokes `reward_per_token()` again. `last_block_reward_applicable(E)` returns `E` (since `M > E`), and `E.ensure_sub(last_update_block=N)` underflows because `N > E`, per `EnsureSub` semantics imported at the top of the module: [5](#0-4) . This returns `DispatchError::Arithmetic(ArithmeticError::Underflow)`, aborting the extrinsic.

Every entry point that touches a staked, non-empty pool routes through `reward_per_token` before mutating state:
- `stake` — `Self::update_pool_and_staker_rewards(&pool_info, &staker_info)?` [6](#0-5) 
- `unstake` — same call [7](#0-6) 
- `harvest_rewards` — same call [8](#0-7) 
- `set_pool_reward_rate_per_block` and `set_pool_expiry_block` (admin-only, but still affected) — `Self::reward_per_token(&pool_info)?` [9](#0-8) 

Since `total_tokens_staked` is only skipped when it is zero (`if pool_info.total_tokens_staked.is_zero() { return Ok(...) }` [10](#0-9) ), and tokens can only be removed via `unstake` — which itself is now permanently reverting — the pool becomes a deadlock: no staker can ever unstake or harvest again, and the admin cannot `cleanup_pool` either, since that requires `PoolStakers::iter_key_prefix(pool_id).next()` to be empty [11](#0-10) .

### Impact Explanation
This is reachable by any ordinary signed account with no privileged role: `stake` requires only `ensure_signed(origin)` [12](#0-11) , and after a pool's normal expiry (an operator-configured, expected event, not an attacker action), a single ordinary post-expiry interaction (e.g. the first staker who calls `unstake`/`harvest_rewards`/`stake` after `expiry_block`) irreversibly bricks the pool for every other participant. Unlike the original Solidity report — where later reward periods let locked-out users eventually reclaim funds — here the bug also blocks `unstake`, so staked tokens frozen under `FreezeReason::Staked` can never be withdrawn once the underflow condition is triggered and `total_tokens_staked` is non-zero. This is an irreversible freezing of user funds for every staker in the pool except the one who happened to interact first after expiry.

### Likelihood Explanation
High. It requires no attacker skill or privileges — it is a deterministic consequence of normal pool lifecycle usage (pool expires, and more than one account has staked tokens in it). Any production deployment of `pallet-asset-rewards` with multiple concurrent stakers in a pool that reaches its `expiry_block` will trigger this on the very next interaction after the first post-expiry call.

### Recommendation
Cap `last_update_block` at `last_block_reward_applicable(pool_info.expiry_block)` inside `update_pool_rewards()`, mirroring the capped read side, instead of storing the raw `T::BlockNumberProvider::current_block_number()`:
```rust
new_pool_info.last_update_block = Self::last_block_reward_applicable(pool_info.expiry_block);
```
This mirrors the Synthetix pattern (`lastUpdateTime = lastTimeRewardApplicable()`) that the report's own recommendation describes, ensuring `last_update_block` never exceeds `expiry_block`, eliminating the underflow for all subsequent callers.

### Proof of Concept
Conceptual reproduction using the pallet's own test harness (`substrate/frame/asset-rewards/src/tests.rs`, `new_test_ext()`):
1. `create_pool` with `expiry_block = E` (e.g. via `create_default_pool()` as used throughout `tests.rs` [13](#0-12) ).
2. `stake` from `staker1` and `staker2` before `E`.
3. Advance `System::set_block_number` to `N1 > E`. Have `staker1` call `harvest_rewards` (or `unstake`) — succeeds, and internally sets `Pools::<T>::get(pool_id).last_update_block = N1` via `update_pool_rewards` (line 780).
4. Advance to `N2 >= N1`. Have `staker2` call `harvest_rewards` (or `unstake`, or `stake`) on the same pool.
5. Expected (per intended design, analogous to Synthetix): `staker2`'s call succeeds and pays out rewards accrued up to `E`.
   Actual: `reward_per_token()` computes `last_block_reward_applicable(E) = E` and then `E.ensure_sub(N1)` where `N1 > E`, returning `Err(DispatchError::Arithmetic(ArithmeticError::Underflow))`, causing `staker2`'s extrinsic to fail — and this failure persists for every future call touching the pool, including `unstake`, permanently freezing `staker2`'s (and any other remaining staker's) frozen/staked tokens.

This reproduction was derived by static analysis of `update_pool_rewards`, `reward_per_token`, and `last_block_reward_applicable` in `substrate/frame/asset-rewards/src/lib.rs`; it was not executed against a live node in this session — a background Devin agent with repository access should add this as a `#[test]` in `substrate/frame/asset-rewards/src/tests.rs` (following the existing `integration()` test pattern at lines 1284-1455) to confirm the `ArithmeticError::Underflow` and permanent-lockout behavior concretely.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L65-79)
```rust
//! ## Rewards Algorithm
//!
//! The rewards algorithm is based on the Synthetix [StakingRewards.sol](https://web.archive.org/web/20251223190741/https://github.com/Synthetixio/synthetix/blob/develop/contracts/StakingRewards.sol)
//! smart contract.
//!
//! Rewards are calculated JIT (just-in-time), and all operations are O(1) making the approach
//! scalable to many pools and stakers.
//!
//! ### Resources
//!
//! - [This video series](https://www.youtube.com/watch?v=6ZO5aYg1GI8), which walks through the math
//!   of the algorithm.
//! - [This dev.to article](https://dev.to/heymarkkop/understanding-sushiswaps-masterchef-staking-rewards-1m6f),
//!   which explains the algorithm of the SushiSwap MasterChef staking. While not identical to the
//!   Synthetix approach, they are quite similar.
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L193-199)
```rust
	use sp_runtime::{
		traits::{
			AccountIdConversion, BadOrigin, EnsureAdd, EnsureAddAssign, EnsureDiv, EnsureMul,
			EnsureSub, EnsureSubAssign,
		},
		DispatchResult,
	};
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L473-474)
```rust
		pub fn stake(origin: OriginFor<T>, pool_id: PoolId, amount: T::Balance) -> DispatchResult {
			let staker = ensure_signed(origin)?;
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L476-480)
```rust
			// Always start by updating staker and pool rewards.
			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			let staker_info = PoolStakers::<T>::get(pool_id, &staker).unwrap_or_default();
			let (mut pool_info, mut staker_info) =
				Self::update_pool_and_staker_rewards(&pool_info, &staker_info)?;
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L523-530)
```rust
			// Always start by updating the pool rewards.
			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			let now = T::BlockNumberProvider::current_block_number();
			ensure!(now > pool_info.expiry_block || caller == staker, BadOrigin);

			let staker_info = PoolStakers::<T>::get(pool_id, &staker).unwrap_or_default();
			let (mut pool_info, mut staker_info) =
				Self::update_pool_and_staker_rewards(&pool_info, &staker_info)?;
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L577-585)
```rust
			// Always start by updating the pool and staker rewards.
			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			let now = T::BlockNumberProvider::current_block_number();
			ensure!(now > pool_info.expiry_block || caller == staker, BadOrigin);

			let staker_info =
				PoolStakers::<T>::get(pool_id, &staker).ok_or(Error::<T>::NonExistentStaker)?;
			let (pool_info, mut staker_info) =
				Self::update_pool_and_staker_rewards(&pool_info, &staker_info)?;
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L700-704)
```rust
			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			ensure!(pool_info.admin == who, BadOrigin);

			let stakers = PoolStakers::<T>::iter_key_prefix(pool_id).next();
			ensure!(stakers.is_none(), Error::<T>::NonEmptyPool);
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L790-792)
```rust
			if pool_info.total_tokens_staked.is_zero() {
				return Ok(pool_info.reward_per_token_stored);
			}
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L793-801)
```rust

			let rewardable_blocks_elapsed: u32 =
				match Self::last_block_reward_applicable(pool_info.expiry_block)
					.ensure_sub(pool_info.last_update_block)?
					.try_into()
				{
					Ok(b) => b,
					Err(_) => return Err(Error::<T>::BlockNumberConversionError.into()),
				};
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L826-833)
```rust
		fn last_block_reward_applicable(pool_expiry_block: BlockNumberFor<T>) -> BlockNumberFor<T> {
			let now = T::BlockNumberProvider::current_block_number();
			if now < pool_expiry_block {
				now
			} else {
				pool_expiry_block
			}
		}
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L953-955)
```rust
		// Always start by updating the pool rewards.
		let reward_per_token = Self::reward_per_token(&pool_info)?;
		let mut pool_info = Self::update_pool_rewards(&pool_info, reward_per_token)?;
```

**File:** substrate/frame/asset-rewards/src/tests.rs (L242-259)
```rust
	#[test]
	fn success_same_assets() {
		new_test_ext().execute_with(|| {
			assert_eq!(NextPoolId::<MockRuntime>::get(), 0);

			System::set_block_number(10);
			let expected_expiry_block = DEFAULT_EXPIRE_AFTER + 10;

			// Create a pool with the same staking and reward asset.
			let asset = NativeOrWithId::<u32>::Native;
			assert_ok!(StakingRewards::create_pool(
				RuntimeOrigin::root(),
				Box::new(asset.clone()),
				Box::new(asset.clone()),
				DEFAULT_REWARD_RATE_PER_BLOCK,
				DispatchTime::After(DEFAULT_EXPIRE_AFTER),
				Some(PermissionedAccountId::get())
			));
```
