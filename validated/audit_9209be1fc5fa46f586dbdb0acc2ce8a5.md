### Title
Staking into an expired `pallet-asset-rewards` pool permanently freezes the staker's tokens and blocks `cleanup_pool` via an arithmetic underflow in `reward_per_token` - (File: substrate/frame/asset-rewards/src/lib.rs)

### Summary
`pallet-asset-rewards::stake` has no check preventing staking into a pool whose `expiry_block` has already passed, and `update_pool_rewards` unconditionally advances `last_update_block` to the current block regardless of whether the pool had any active stake. This mirrors the root cause pattern in the `MuteAmplifier` report (an incorrectly-scoped check allows a "first stake" after the reward period has effectively ended), and produces a worse practical outcome: the newly-staked tokens become permanently frozen and the pool can never be cleaned up.

### Finding Description
`stake()` [1](#0-0)  takes any signed account, looks up the pool, and calls `update_pool_and_staker_rewards` before applying the freeze — there is no `ensure!(now <= pool_info.expiry_block, ...)` guard anywhere in this call, unlike `unstake`/`harvest_rewards` which only gate *who* may call them post-expiry [2](#0-1) .

`update_pool_rewards` unconditionally sets `last_update_block` to the current block number, even when `total_tokens_staked` was zero at call time (early-return path in `reward_per_token` skips only the reward-per-token math, not the block-number bump): [3](#0-2) 

Consequence: whenever a pool's `total_tokens_staked` reaches zero after `expiry_block` (either because every prior staker fully unstaked, or because it is a brand-new pool nobody staked into before expiry) and someone then calls `stake()` on that already-expired pool, `update_pool_rewards` sets `last_update_block` to the current (post-expiry) block number, which is now **greater than** `pool_info.expiry_block`.

On the very next reward-computing call for that pool (another `stake`, `unstake`, or `harvest_rewards`, since `total_tokens_staked` is now nonzero), `reward_per_token` computes:
```
last_block_reward_applicable(expiry_block).ensure_sub(last_update_block)
```
`last_block_reward_applicable` caps at `expiry_block` [4](#0-3) , which is now *smaller* than `last_update_block`, so `ensure_sub` underflows and returns `DispatchError` from `reward_per_token` [5](#0-4) . This error propagates through `update_pool_and_staker_rewards` [6](#0-5) , so **every** subsequent `stake`, `unstake`, and `harvest_rewards` call on that pool fails permanently — including the staker's own attempt to unstake, since `unstake()` calls the same update routine before reaching `T::AssetsFreezer::decrease_frozen` [7](#0-6) .

Because the staker can never successfully unstake, `PoolStakers` for that pool can never be emptied, so `cleanup_pool` — the pallet's analog to `rescueTokens` — is permanently blocked by its `stakers.is_none()` guard, and the admin can never recover the remaining reward-asset balance in the pool account: [8](#0-7) 

This is a structurally identical bug class to the referenced MuteAmplifier finding: a permissionless "stake" action that is allowed after the reward period has effectively ended, on a pool with zero current participants, poisons pool state so that the protocol's terminal/cleanup path can never succeed — except here the impact is compounded because the staker's own principal (not just the reward pot) becomes permanently frozen too.

### Impact Explanation
- The staker's own staked (frozen) tokens become permanently unrecoverable — no extrinsic path exists to call `decrease_frozen` on them once `reward_per_token` starts erroring.
- The pool's reward-asset balance held in the pool account (deposited via `deposit_reward_tokens`) becomes permanently unrecoverable because `cleanup_pool` requires an empty `PoolStakers` map that can no longer be achieved.
- This can be triggered unintentionally (any user staking into an expired-but-currently-empty pool) or deliberately by an attacker front-running `cleanup_pool`, at the cost of only the amount they choose to stake (which they then also permanently lose).
- No privileged role, governance action, or malicious peer/collator is required — a normal signed `stake` extrinsic from an unprivileged account triggers it.

### Likelihood Explanation
Likelihood is high for any long-running or admin-managed `asset-rewards` pool: pools naturally reach `total_tokens_staked == 0` after expiry (all participants harvest/unstake), and nothing in `stake()` prevents further staking into an expired pool. No special timing or privileged access is needed — only that `total_tokens_staked` is zero at the moment of the post-expiry stake, and any block gap between that stake and the next reward-computing call.

### Recommendation
- Add an explicit check in `stake()` rejecting stakes where `now > pool_info.expiry_block` (mirroring the intended check the MuteAmplifier report says should exist, rather than omitting it).
- Alternatively/additionally, fix `update_pool_rewards`/`reward_per_token` so `last_update_block` is never advanced past `expiry_block`, and use saturating (not `ensure_sub`) semantics for `rewardable_blocks_elapsed`, or clamp `last_update_block` to `min(last_update_block, expiry_block)` before the subtraction, so the computation can never underflow regardless of when pool state was last touched.

### Proof of Concept
Not executed against a live network. Reasoning is based on static trace of the pallet's own logic, cross-checked against `substrate/frame/asset-rewards/src/tests.rs`, which contains no test covering "stake into an already-expired pool with zero current stake, then attempt to unstake/harvest again" — the `extends_reward_accumulation` and `integration` tests only cover extending expiry, not staking after a permanent expiry with zero participants. A minimal reproduction (not run here) would be, in the pallet's existing `new_test_ext()` mock:
1. `create_pool` with a short `expiry_block`.
2. Advance blocks past `expiry_block` (pool has zero stakers throughout).
3. `stake(origin: staker, pool_id, amount)` — succeeds because `stake()` has no expiry guard; this sets `last_update_block = now` (> `expiry_block`).
4. Advance one more block; call `unstake(origin: staker, pool_id, amount, None)`.
5. Expected: either success (funds returned) or a graceful error preserving user ability to retry.
6. Actual (per code trace): `reward_per_token` computes `expiry_block.ensure_sub(last_update_block)` which underflows, `unstake` returns `DispatchError::Arithmetic(Underflow)`, and this failure is permanent for the pool — repeating step 4 always fails, and `cleanup_pool` also fails forever due to the un-emptiable `PoolStakers` map.

I was not able to execute this scenario in a live test harness within this session; the control-flow and arithmetic trace above is derived directly from the cited source lines and is deterministic given the described state transitions. Confirmation via an actual `#[test]` run in `substrate/frame/asset-rewards/src/tests.rs` is recommended before filing.

### Citations

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

**File:** substrate/frame/asset-rewards/src/lib.rs (L514-541)
```rust
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

			// Check the staker has enough staked tokens.
			ensure!(staker_info.amount >= amount, Error::<T>::NotEnoughTokens);

			// Unfreeze staker assets.
			T::AssetsFreezer::decrease_frozen(
				pool_info.staked_asset_id.clone(),
				&FreezeReason::Staked.into(),
				&staker,
				amount,
			)?;
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L696-729)
```rust
		#[pallet::call_index(8)]
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L754-765)
```rust
		pub fn update_pool_and_staker_rewards(
			pool_info: &PoolInfoFor<T>,
			staker_info: &PoolStakerInfo<T::Balance>,
		) -> Result<(PoolInfoFor<T>, PoolStakerInfo<T::Balance>), DispatchError> {
			let reward_per_token = Self::reward_per_token(&pool_info)?;
			let pool_info = Self::update_pool_rewards(pool_info, reward_per_token)?;

			let mut new_staker_info = staker_info.clone();
			new_staker_info.rewards = Self::derive_rewards(&staker_info, &reward_per_token)?;
			new_staker_info.reward_per_token_paid = pool_info.reward_per_token_stored;
			return Ok((pool_info, new_staker_info));
		}
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L775-810)
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
