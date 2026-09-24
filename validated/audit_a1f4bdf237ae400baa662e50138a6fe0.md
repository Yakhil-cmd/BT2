### Title
Reward-per-token index overflow in `pallet-asset-rewards` permanently freezes staked funds when pool stake is dust - (File: `substrate/frame/asset-rewards/src/lib.rs`)

### Summary
`pallet-asset-rewards` (wired into `asset-hub-rococo`, `asset-hub-westend`, `substrate/bin/node/runtime`, and the `staking-async` parachain runtime) computes a per-block reward index (`reward_per_token_stored`) using checked arithmetic (`ensure_mul`/`ensure_div`/`ensure_add`) instead of saturating/capping arithmetic. When a pool's `total_tokens_staked` is dust (e.g. `1`), the division amplifies the numerator so heavily that `ensure_add` overflows `T::Balance`, causing `reward_per_token()` to return `Err(ArithmeticError::Overflow)`. Because `reward_per_token()` is called unconditionally at the top of `stake`, `unstake`, and `harvest_rewards`, once this overflow condition is triggered, **every subsequent call to these extrinsics for that pool reverts forever** — permanently freezing any staker's `AssetsFreezer`-frozen tokens in that pool (they can never call `unstake` successfully again). This is the FRAME analog of the reported Aave `RewardsDistributor` bug (index overflow when asset total supply is dust), but worse in impact: instead of the reward index silently saturating/DoS'ing accrual (as in Solidity), Substrate's checked arithmetic makes the extrinsic itself permanently fail, freezing user funds rather than merely stalling reward emission.

### Finding Description
The reward formula in `reward_per_token()`: [1](#0-0) 

```rust
pub(super) fn reward_per_token(
    pool_info: &PoolInfoFor<T>,
) -> Result<T::Balance, DispatchError> {
    if pool_info.total_tokens_staked.is_zero() {
        return Ok(pool_info.reward_per_token_stored);
    }
    ...
    Ok(pool_info.reward_per_token_stored.ensure_add(
        pool_info
            .reward_rate_per_block
            .ensure_mul(rewardable_blocks_elapsed.into())?
            .ensure_mul(PRECISION_SCALING_FACTOR.into())?
            .ensure_div(pool_info.total_tokens_staked)?,
    )?)
}
```

`total_tokens_staked` is fully attacker-controlled: any signed account can `stake`/`unstake` arbitrary amounts with no minimum-stake enforcement (`substrate/frame/asset-rewards/src/lib.rs:473-560`). An attacker can:

1. Stake a minimal amount (e.g. `1`) into a pool, or wait until they are the last/only staker so `total_tokens_staked` becomes dust (`1`).
2. Let a normal amount of time (blocks) pass — no cost to the attacker; this is a permissionless waiting condition.
3. Any subsequent call to `stake`, `unstake`, or `harvest_rewards` on that pool (by the attacker or any other staker) invokes `Self::update_pool_and_staker_rewards` → `Self::reward_per_token`: [2](#0-1) 

Because `total_tokens_staked` divides the numerator (`reward_rate_per_block * blocks_elapsed * PRECISION_SCALING_FACTOR`), a dust denominator massively amplifies the resulting per-token increment before it is added to the accumulated `reward_per_token_stored`. Once this addition exceeds `T::Balance::MAX`, `ensure_add` returns `Err`, and the whole extrinsic (`stake`/`unstake`/`harvest_rewards`) fails with `ArithmeticError::Overflow`, exactly the same as it would for `set_pool_reward_rate_per_block`/`set_pool_expiry_block` since they also call `reward_per_token` first (`substrate/frame/asset-rewards/src/lib.rs:900-963`).

Crucially, `unstake` is the only path to release the `AssetsFreezer` freeze placed during `stake`: [3](#0-2) 

Since `unstake` also calls `update_pool_and_staker_rewards` before doing anything else, once the index overflows, stakers can no longer unstake — their tokens remain permanently frozen. There is no admin recovery path in the pallet for this state (`cleanup_pool` requires zero stakers, which can never be reached because nobody can unstake).

This mirrors the reported invariant violation ("index computed from `emission * time / totalSupply` can reach the max representable value when `totalSupply` is dust") but the FRAME implementation's use of checked/`ensure_*` arithmetic converts what in Solidity is "rewards stop accruing" into "the extrinsic reverts forever," which is strictly worse: it is a fund-freezing DoS rather than merely a stalled-emission DoS.

### Impact Explanation
This is a Denial-of-Service against pallet-asset-rewards pools that permanently freezes staked user funds (via `AssetsFreezer`) with no recovery mechanism once triggered, in a pallet that is live in `asset-hub-rococo` and `asset-hub-westend` production runtimes. No privileged role, governance action, or malicious infrastructure is required — an ordinary signed account controls `total_tokens_staked` dust conditions simply through normal `stake`/`unstake` usage and the passage of time.

### Likelihood Explanation
Reachability depends on pool parameters (`reward_rate_per_block`, `PRECISION_SCALING_FACTOR = 4096`) set by the pool admin (via `CreatePoolOrigin`/admin calls) and elapsed blocks, combined with an attacker-controllable dust `total_tokens_staked`. I could not fully determine from static inspection alone the exact minimum `reward_rate_per_block` / elapsed-block combination needed to overflow `T::Balance` (confirmed as `u128` for Balances in the wired runtimes) with `total_tokens_staked = 1`; a concrete numeric threshold and a runnable overflow reproduction using the pallet's test harness (`substrate/frame/asset-rewards/src/tests.rs`, `mock.rs`) would be needed to fully confirm likelihood and is left as a follow-up for a maintainer/researcher with execution access, since I do not have tool access to run Rust tests in this environment.

### Recommendation
- Use saturating arithmetic (cap at `T::Balance::MAX`) for `reward_per_token_stored` instead of `ensure_add`, so that pool operations never hard-fail due to index overflow, and/or
- Enforce a minimum non-dust `total_tokens_staked` floor (return `reward_per_token_stored` unchanged, similar to the existing `is_zero()` short-circuit, when `total_tokens_staked` is below a configured threshold), and/or
- Decouple the "index update" step from the "freeze/withdraw" step in `unstake`, so that even if reward accounting fails, a staker can still recover their frozen principal (defense in depth against future arithmetic issues in the reward path).

### Proof of Concept
I was not able to execute a runnable reproduction in this environment (no code execution / terminal access available for this ask-only analysis). The concrete steps that would need to be validated with the existing pallet test harness (`substrate/frame/asset-rewards/src/{tests.rs,mock.rs}`) are:
1. Create a pool with a `reward_rate_per_block` and `expiry_block` sufficiently far in the future.
2. Have a single staker `stake(pool_id, 1)` so `total_tokens_staked == 1`.
3. Advance blocks (via `System::set_block_number`) far enough that `reward_rate_per_block * blocks_elapsed * 4096 / 1` plus the existing `reward_per_token_stored` exceeds `T::Balance::MAX` (u128 in the wired runtimes).
4. Call `unstake` and confirm it returns `Err(DispatchError::Arithmetic(ArithmeticError::Overflow))` instead of succeeding, and that no further `unstake` call can ever succeed for that staker, demonstrating permanent freezing of the `AssetsFreezer`-locked tokens.

This PoC was not executed; the guard conditions and code paths (`ensure_mul`/`ensure_div`/`ensure_add` in `reward_per_token`, and its unconditional call at the top of `stake`/`unstake`/`harvest_rewards`) are directly cited above from the pallet source and support the described failure mode, but the exact numeric parameters required to trigger the overflow within a realistic timeframe have not been empirically confirmed.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L513-545)
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

			// Check the staker has enough staked tokens.
			ensure!(staker_info.amount >= amount, Error::<T>::NotEnoughTokens);

			// Unfreeze staker assets.
			T::AssetsFreezer::decrease_frozen(
				pool_info.staked_asset_id.clone(),
				&FreezeReason::Staked.into(),
				&staker,
				amount,
			)?;

			// Update Pools.
			pool_info.total_tokens_staked.ensure_sub_assign(amount)?;
			Pools::<T>::insert(pool_id, pool_info);
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L746-765)
```rust
		/// Computes update pool and staker reward state.
		///
		/// Should be called prior to any operation involving a staker.
		///
		/// Returns the updated pool and staker info.
		///
		/// NOTE: this function has no side-effects. Side-effects such as storage modifications are
		/// the responsibility of the caller.
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
