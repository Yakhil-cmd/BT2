Based on my analysis, there is a demonstrable analog in `pallet-asset-rewards`'s `cleanup_pool` extrinsic that mirrors the report's core invariant violation: **an unprivileged, permissionless action by an attacker leaves a persistent state entry that permanently blocks a legitimate administrative action which is gated on that state being empty.**

### Title
DOS of `cleanup_pool()` via griefing `stake()` to keep `PoolStakers` non-empty - ([File: substrate/frame/asset-rewards/src/lib.rs])

### Summary
`pallet-asset-rewards::cleanup_pool` (admin-only) requires `PoolStakers` to have no entries for the pool before it can reclaim the pool's remaining reward-asset balance and remove the `Pools` storage entry. Because `stake()` is a fully permissionless, signed extrinsic open to anyone holding a nonzero amount of the staking asset, an attacker can call `stake(pool_id, tiny_amount)` at any time (including immediately after the admin unstakes/harvests all "real" stakers) to recreate a `PoolStakers` entry, causing `cleanup_pool` to revert with `Error::NonEmptyPool` indefinitely.

### Finding Description
`cleanup_pool` is defined at [1](#0-0) . It requires the caller to be the pool admin, then checks `PoolStakers::<T>::iter_key_prefix(pool_id).next()` is `None` via `Error::<T>::NonEmptyPool`, and only then transfers the pool's remaining reward-asset balance out and removes the `Pools` entry.

The `PoolStakers` map, however, is populated by the fully permissionless `stake` extrinsic at [2](#0-1) . Any signed account holding a nonzero amount of `staked_asset_id` can call `stake` with an arbitrarily small `amount` (there is no minimum-stake check), which inserts an entry into `PoolStakers::<T>` for `(pool_id, staker)`.

This is structurally identical to the reported bug class: the removal/cleanup path performs an emptiness check on state that an attacker fully controls via a normal, unprivileged, low-cost user action (equivalent to sending "1 wei" of `vaultAsset` to keep `balanceOf(this) > 0`). Here the attacker "sends 1 unit" of the staking asset via `stake()` to keep `PoolStakers` non-empty, permanently blocking `cleanup_pool`.

### Impact Explanation
The pool admin can never call `cleanup_pool` to reclaim the unutilized reward-asset balance nor remove the `Pools::<T>` storage entry, as long as an attacker re-stakes a dust amount after every unstake. This is a functional/logical DOS on an admin-facing cleanup extrinsic, consistent with the "Medium" bug class of the source report (unbounded blocking of a legitimate state-transition function via cheap, permissionless griefing), though it does not cause theft or unbacked issuance. There is no unbounded storage growth per se — the attacker only maintains a single `PoolStakers` entry — so this stays a targeted logic DOS rather than a resource-exhaustion claim.

### Likelihood Explanation
High likelihood in any deployment where `cleanup_pool` is expected to be callable once a pool is done. `stake` has no minimum amount requirement and is open to any signed account with `>0` of the staking asset, making the griefing extremely cheap (a small stake, subject only to freeze/lock of that amount, which the attacker can later reclaim via `unstake` and can also immediately restake with the same tiny amount in the very next block or transaction).

### Recommendation
Do not gate `cleanup_pool` purely on `PoolStakers` emptiness controlled by third parties. Options: (a) allow cleanup irrespective of stray dust stakes below a minimum threshold, only requiring the "real"/pre-expiry stakers to be cleared and ignoring post-expiry dust stakes; (b) enforce a nonzero minimum stake amount and/or restrict `stake()` after pool expiry (`now > pool_info.expiry_block`) so it can no longer be called once cleanup is expected, mirroring the existing `unstake`/`harvest_rewards` restriction (`ensure!(now > pool_info.expiry_block || caller == staker, BadOrigin)` — but note this restriction is on the caller for staker-owned rewards, not preventing new stakes); (c) use an internal, admin/authorized-controlled accounting for "active stakers" rather than a raw, permissionless-writable storage prefix as the sole liveness check.

### Proof of Concept
No local reproduction was executed. This is inferred from static code review:
- `stake` at [3](#0-2)  is `ensure_signed`-gated only, with no expiry check and no minimum amount — callable at any time by anyone holding the staking asset.
- `cleanup_pool` at [1](#0-0)  requires `PoolStakers::<T>::iter_key_prefix(pool_id).next().is_none()` via `Error::<T>::NonEmptyPool` at line ~704.
- Sequence: admin's legitimate stakers `unstake` fully (removing their `PoolStakers` entries per [4](#0-3) ) → attacker calls `stake(pool_id, 1)` → `cleanup_pool` reverts with `NonEmptyPool` → admin is permanently blocked from reclaiming remaining reward assets and removing the pool.

I was not able to execute this against the pallet's test harness (`substrate/frame/asset-rewards/src/tests.rs`) within this session; a background Devin agent with terminal access could add a test reproducing this exact griefing sequence to confirm the revert and the permanent blocking behavior.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L469-502)
```rust
		/// Stake additional tokens in a pool.
		///
		/// A freeze is placed on the staked tokens.
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L550-554)
```rust
			if staker_info.amount.is_zero() && staker_info.rewards.is_zero() {
				PoolStakers::<T>::remove(&pool_id, &staker);
			} else {
				PoolStakers::<T>::insert(&pool_id, &staker, staker_info);
			}
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
