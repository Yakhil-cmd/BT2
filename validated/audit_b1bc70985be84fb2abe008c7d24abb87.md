### Title
Permanent freeze of staked/reward assets in `pallet-asset-rewards` due to unbounded `last_update_block` after pool expiry - ([File: substrate/frame/asset-rewards/src/lib.rs])

### Summary
`pallet-asset-rewards` computes accrued rewards the same way as the SNX contract in the referenced report: `reward_per_token = rate * (last_block_reward_applicable(expiry) - last_update_block)`. Just like `lastUpdateTime` in the SNX bug, `last_update_block` is stamped with the *actual* current block on every mutating call, even when the pool has already expired, instead of being capped at `expiry_block`. Once a single call happens after expiry, `last_update_block` ends up strictly greater than the stored `expiry_block`. Every subsequent call that touches the pool (`stake`, `unstake`, `harvest_rewards`, `set_pool_reward_rate_per_block`, `set_pool_expiry_block`) recomputes `reward_per_token` via `Self::last_block_reward_applicable(pool_info.expiry_block).ensure_sub(pool_info.last_update_block)`, which underflows because `expiry_block < last_update_block`. `ensure_sub` returns an `ArithmeticError` and the whole extrinsic fails, permanently bricking the pool.

### Finding Description
- `reward_per_token` computes rewardable blocks as `last_block_reward_applicable(pool_info.expiry_block).ensure_sub(pool_info.last_update_block)`, where `last_block_reward_applicable` caps at `min(now, expiry_block)`. [1](#0-0) 
- `update_pool_rewards` unconditionally stamps `last_update_block` with the real current block number, not capped at `expiry_block`: [2](#0-1) 
- `harvest_rewards` is explicitly permissionless once the pool has expired (`now > pool_info.expiry_block || caller == staker`), so *any* signed account, without holding a stake or any privileged role, can trigger `update_pool_and_staker_rewards` on an expired pool: [3](#0-2) 
- `unstake` has the same permissionless-post-expiry gate and also goes through `update_pool_and_staker_rewards` before any other logic: [4](#0-3) 
- `set_pool_expiry_block` (the only way to "cure" an expired pool) also calls `Self::reward_per_token(&pool_info)` against the *old, still-stored* `expiry_block` before updating it: [5](#0-4) 
- `cleanup_pool` requires zero stakers before it can reclaim the pool's remaining reward-asset balance: [6](#0-5) 

Sequence:
1. Pool is created with `expiry_block = E`, has stakers and deposited reward tokens.
2. Time passes so current block `now1 > E` (no privileged action required — pools just expire).
3. Any account calls a mutating extrinsic that reaches `update_pool_and_staker_rewards`/`update_pool_rewards` (e.g. a staker calling `unstake`, or literally anyone calling `harvest_rewards` on the staker's behalf, since it is explicitly allowed for any caller once expired). This call succeeds (rewards correctly capped at `E`), but stores `last_update_block = now1`, which is `> E`.
4. Any further call that reaches `reward_per_token` — including `set_pool_expiry_block`, which is the *only* function that could otherwise "revive" the pool — computes `last_block_reward_applicable(E) = min(now2, E) = E` and then `E.ensure_sub(now1)`, which underflows since `now1 > E`. `ensure_sub` returns `Err(ArithmeticError)`, which propagates via `?` and aborts the extrinsic.
5. From this point, `stake`, `unstake`, `harvest_rewards`, `set_pool_reward_rate_per_block`, and `set_pool_expiry_block` all fail unconditionally and forever, because the stored `expiry_block` never changes and `last_update_block` never decreases.
6. Because `unstake` is permanently blocked, `PoolStakers` can never be emptied, so `cleanup_pool`'s precondition (`stakers.is_none()`) can never be satisfied, permanently locking the reward-asset balance held in the pool's account, and permanently freezing every staker's frozen staked-asset balance (the `FreezeReason::Staked` freeze can never be released via `decrease_frozen` in `unstake`).

This is the same root-cause pattern as the SNX report: a time/period accounting value (`lastUpdateTime` / `last_update_block`) is allowed to advance past the boundary of the current reward period without being clamped, causing state inconsistency across period transitions. In the EVM case the missing clamp caused overpayment; in this Substrate case, the checked-arithmetic guard (`ensure_sub`) converts the same missing clamp into a hard, irrecoverable failure mode instead — funds are frozen rather than over-distributed.

### Impact Explanation
Any FRAME-based runtime that includes `pallet-asset-rewards` (e.g. Asset Hub runtimes referenced in the repo, `cumulus/parachains/runtimes/assets/asset-hub-*`) is affected. Once a pool naturally expires and receives a single post-expiry interaction (which is a completely normal, expected occurrence — a staker unstaking after expiry, or anyone harvesting rewards on a staker's behalf after expiry), the pool becomes permanently unusable: staked assets remain frozen forever, unclaimed/unharvested reward tokens remain locked in the pool account forever, and the pool's storage/deposit (`PoolCost`) can never be released via `cleanup_pool`. This is an irreversible freezing of user funds requiring no privileged role, governance action, or malicious external actor — only the natural passage of time past `expiry_block`.

### Likelihood Explanation
High. No attacker privilege is needed; the trigger condition (`now > expiry_block`) is the pool's normal end-of-life state, and the very extrinsics stakers are expected to call at that point (`unstake`, `harvest_rewards`) are what corrupts `last_update_block`. The permissionless-once-expired design of `unstake`/`harvest_rewards` means any third party (not just the staker) can also trigger the corrupting call, and once corrupted, no admin action can reverse it.

### Recommendation
Clamp `last_update_block` to `min(now, expiry_block)` in `update_pool_rewards` (mirroring `last_block_reward_applicable`), so it is never advanced past the pool's `expiry_block`. This is the direct FRAME analog of the report's recommendation to "enforce each period start exactly at the end of the previous period" — here, ensure the stored update timestamp never exceeds the period's own end boundary, preventing the underflow and the resulting permanent freeze.

### Proof of Concept
No local Rust/FRAME integration test was executed in this session; the analysis is based on static code inspection of `substrate/frame/asset-rewards/src/lib.rs` (functions `reward_per_token`, `update_pool_rewards`, `last_block_reward_applicable`, `unstake`, `harvest_rewards`, `set_pool_expiry_block`, `cleanup_pool`) and the existing pallet test suite in `substrate/frame/asset-rewards/src/tests.rs`, which exercises expiry/extension flows but does not cover the specific ordering "expire → single post-expiry mutating call → second mutating call" that triggers the underflow. A concrete reproduction would use the pallet's own mock runtime (`new_test_ext()` in `tests.rs`): create a pool with a short `expiry_block`, stake, advance `System::set_block_number` past expiry, call `unstake` (succeeds, corrupts `last_update_block`), then call `unstake` again or `set_pool_expiry_block` and assert it returns an `ArithmeticError`/`DispatchError` rather than succeeding — confirming the pool is permanently bricked. This was not executed against the actual test harness in this session; the conclusion is derived from tracing the arithmetic and control flow directly, not from an executed test run.

### Citations

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

**File:** substrate/frame/asset-rewards/src/lib.rs (L794-810)
```rust
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L940-963)
```rust
	fn set_pool_expiry_block(
		admin: &T::AccountId,
		pool_id: PoolId,
		new_expiry: DispatchTime<BlockNumberFor<T>>,
	) -> DispatchResult {
		let now = T::BlockNumberProvider::current_block_number();
		let new_expiry_block = new_expiry.evaluate(now);
		ensure!(new_expiry_block > now, Error::<T>::ExpiryBlockMustBeInTheFuture);

		let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
		ensure!(pool_info.admin == *admin, BadOrigin);
		ensure!(new_expiry_block > pool_info.expiry_block, Error::<T>::ExpiryCut);

		// Always start by updating the pool rewards.
		let reward_per_token = Self::reward_per_token(&pool_info)?;
		let mut pool_info = Self::update_pool_rewards(&pool_info, reward_per_token)?;

		pool_info.expiry_block = new_expiry_block;
		Pools::<T>::insert(pool_id, pool_info);

		Self::deposit_event(Event::PoolExpiryBlockModified { pool_id, new_expiry_block });

		Ok(())
	}
```
