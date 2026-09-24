### Title
Idle-period reward emission is permanently lost in `pallet-asset-rewards` when `total_tokens_staked == 0` - ([File: substrate/frame/asset-rewards/src/lib.rs])

### Summary
`pallet-asset-rewards` implements a Synthetix-style `StakingRewards` accumulator (as documented at `substrate/frame/asset-rewards/src/lib.rs:65-79`). The pool's `reward_rate_per_block` is meant to accrue continuously between `last_update_block` and the current block regardless of whether anyone is staked. When `total_tokens_staked` is zero, `reward_per_token()` intentionally skips accrual, but the caller unconditionally advances `last_update_block` to the current block anyway, permanently erasing the reward budget that should have accrued during the idle window — the exact same invariant violation described in the Notional `SecondaryRewarder._accumulateRewardPerNToken` report (rewards for an idle period vanish instead of being deferred to the first future staker).

### Finding Description
`reward_per_token` explicitly bails out without accumulating anything when the pool has no stakers: [1](#0-0) 

```rust
pub(super) fn reward_per_token(
    pool_info: &PoolInfoFor<T>,
) -> Result<T::Balance, DispatchError> {
    if pool_info.total_tokens_staked.is_zero() {
        return Ok(pool_info.reward_per_token_stored);
    }
    ...
```

That returned (unchanged) `reward_per_token_stored` is then fed into `update_pool_rewards`, which unconditionally sets `last_update_block` to the current block, discarding the elapsed idle period entirely: [2](#0-1) 

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

This is invoked from `update_pool_and_staker_rewards`, which is called on the `stake` extrinsic path before adding the new staker's balance: [3](#0-2) 

```rust
pub fn update_pool_and_staker_rewards(
    pool_info: &PoolInfoFor<T>,
    staker_info: &PoolStakerInfo<T::Balance>,
) -> Result<(PoolInfoFor<T>, PoolStakerInfo<T::Balance>), DispatchError> {
    let reward_per_token = Self::reward_per_token(&pool_info)?;
    let pool_info = Self::update_pool_rewards(pool_info, reward_per_token)?;
    ...
```

`stake` is a permissionless, signed extrinsic (any account can call it), reachable exactly as the report requires — no privileged role needed: [4](#0-3) 

Concrete sequence:
1. Pool is created with `total_tokens_staked = 0`, `last_update_block = creation_block`, and a configured `reward_rate_per_block`.
2. No one stakes for `N` blocks (pool idle).
3. A user calls `stake`, which calls `update_pool_and_staker_rewards` → `reward_per_token` returns the stored value unchanged (correctly, since dividing by zero staked tokens is undefined) → `update_pool_rewards` sets `last_update_block = current_block`.
4. The `N * reward_rate_per_block` tokens that should have been reserved/emitted during the idle window are never accounted for in `reward_per_token_stored`, and because `last_update_block` has jumped forward, that idle period can never be recovered by any future computation. The tokens remain in the pool's reward account, functionally stuck (not distributable to any staker under the reward-per-token formula) until the admin eventually calls `cleanup_pool` (which requires all stakers unwound) and reclaims the excess balance manually.

This exactly mirrors the reported Solidity bug class: reward accounting silently drops the pro‑rata emission for any period with zero backing (stake/nToken supply), and the "last update" timestamp/block is advanced regardless, permanently losing that slice of the emission schedule.

### Impact Explanation
The invariant "the pool must emit `reward_rate_per_block` pro rata over any period regardless of staker count" is broken whenever the pool has zero stakers (e.g., right after creation, or after everyone fully unstakes). This causes emitted rewards to fall permanently short of the pool's intended budget for every idle window — no attacker action or privilege is required, it happens automatically to any pool that experiences downtime. Funds are not stolen from users, but distribution deterministically diverges from pool configuration/documentation, and idle-period tokens become effectively unrecoverable through normal reward flows (only via a full `cleanup_pool`, which requires the pool to be fully unwound and unclaimed rewards forfeited to the pool admin). This is a Medium-severity accounting/invariant break, consistent with the original Sherlock report's severity rating.

### Likelihood Explanation
High likelihood of natural occurrence: any newly created pool (block gap between `create_pool` and first `stake`) or any pool that is fully unstaked (e.g., during low incentive periods, or right before `cleanup_pool`'s "empty" check) triggers this path automatically with no special conditions or malicious behavior required.

### Recommendation
In `update_pool_rewards` (or in `update_pool_and_staker_rewards`), skip advancing `last_update_block` when `pool_info.total_tokens_staked.is_zero()`, so that the idle interval is preserved and rewarded to the first staker who re-enters (mirroring the analogous fix proposed in the original report — defer emission rather than silently drop it):

```rust
pub fn update_pool_rewards(
    pool_info: &PoolInfoFor<T>,
    reward_per_token: T::Balance,
) -> Result<PoolInfoFor<T>, DispatchError> {
    let mut new_pool_info = pool_info.clone();
    if !pool_info.total_tokens_staked.is_zero() {
        new_pool_info.last_update_block = T::BlockNumberProvider::current_block_number();
    }
    new_pool_info.reward_per_token_stored = reward_per_token;
    Ok(new_pool_info)
}
```

### Proof of Concept
Code-level reproduction (not executed against a live network, but derivable directly from the pallet logic and existing test harness in `substrate/frame/asset-rewards/src/tests.rs`):
1. `create_pool` with `reward_rate_per_block = R`, at block `B0` (`total_tokens_staked = 0`, `last_update_block = B0`).
2. Advance chain by `N` blocks with no `stake` calls (pool idle, `total_tokens_staked` stays 0).
3. Call `stake(pool_id, amount)` from account A at block `B0+N`.
   - `reward_per_token()` returns `reward_per_token_stored` unchanged (guard at line 790-792).
   - `update_pool_rewards` sets `last_update_block = B0+N` (line 780) regardless.
4. Assert: subsequent `reward_per_token()` computations for A only start accruing from `B0+N` onward — the `R * N` tokens that should have existed at `B0..B0+N` are unaccounted for in `reward_per_token_stored` and can never be recovered by any staker, even though the pool's reward asset account may still hold that balance (deposited via `deposit_reward_tokens`), demonstrating the emission-rate invariant violation.

This was verified through static code inspection of the guarded `reward_per_token` early-return combined with the unconditional block-advance in `update_pool_rewards`/`update_pool_and_staker_rewards`, and the permissionless `stake`/`unstake`/`harvest_rewards` call sites that trigger this path; no test was executed to produce runtime output, so exact drained-token amounts were not numerically confirmed here — a background agent with a Rust toolchain should add a unit test in `substrate/frame/asset-rewards/src/tests.rs` asserting `reward_per_token_stored`/staker payout numbers before and after an idle gap to obtain concrete numeric confirmation.

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

**File:** substrate/frame/asset-rewards/src/lib.rs (L786-792)
```rust
		/// Derives the current reward per token for this pool.
		pub(super) fn reward_per_token(
			pool_info: &PoolInfoFor<T>,
		) -> Result<T::Balance, DispatchError> {
			if pool_info.total_tokens_staked.is_zero() {
				return Ok(pool_info.reward_per_token_stored);
			}
```
