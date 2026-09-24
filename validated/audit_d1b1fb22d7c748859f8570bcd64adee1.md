## Analysis Summary

The Sherlock report's core defect pattern is: **a monotonic-accumulator subtraction that is protected by "safe" (reverting) arithmetic instead of saturating arithmetic, causing legitimate user transactions to permanently revert.** Searching the Polkadot SDK for pallets that reproduce the same pattern (fee/reward accounting with `ensure_sub`/checked subtraction instead of `saturating_sub`), the closest and demonstrable analog is in `pallet-asset-rewards` (`substrate/frame/asset-rewards`), where the "blocks elapsed" calculation used to accrue the reward accumulator is subject to exactly this class of failure once a pool has expired. [1](#0-0) [2](#0-1) 

### Title
Permanent underflow revert of `reward_per_token()` after pool expiry locks stakers out of `unstake`/`harvest_rewards` in `pallet-asset-rewards` - (File: `substrate/frame/asset-rewards/src/lib.rs`)

### Summary
`update_pool_rewards` unconditionally sets `last_update_block` to the *unclamped* current block number, even when the pool has already passed its `expiry_block`. On the following state-mutating call (`stake`, `unstake`, `harvest_rewards`, `set_pool_reward_rate_per_block`, `set_pool_expiry_block`), `reward_per_token()` computes `last_block_reward_applicable(expiry_block).ensure_sub(last_update_block)`, which is `expiry_block - last_update_block` — a negative value in unsigned arithmetic. `ensure_sub` (unlike `saturating_sub`) returns `ArithmeticError::Underflow`, causing the entire extrinsic to fail. This is the same root-cause class as the Sherlock report: a delta computed from an accumulator/timestamp is protected by checked arithmetic that disallows a case the algorithm actually needs to tolerate, and reverts a legitimate user transaction. Unlike the Sherlock report, here the effect is not marginal — it permanently DoSes `unstake` and `harvest_rewards`, freezing user funds.

### Finding Description
`reward_per_token()`:
```rust
let rewardable_blocks_elapsed: u32 =
    match Self::last_block_reward_applicable(pool_info.expiry_block)
        .ensure_sub(pool_info.last_update_block)?
        .try_into()
``` [3](#0-2) 

`last_block_reward_applicable` returns `min(now, expiry_block)`:
```rust
fn last_block_reward_applicable(pool_expiry_block: BlockNumberFor<T>) -> BlockNumberFor<T> {
    let now = T::BlockNumberProvider::current_block_number();
    if now < pool_expiry_block { now } else { pool_expiry_block }
}
``` [4](#0-3) 

But `update_pool_rewards`, which persists `last_update_block` after every reward computation, stores the **raw, unclamped** current block number, not `last_block_reward_applicable`:
```rust
pub fn update_pool_rewards(...) -> Result<PoolInfoFor<T>, DispatchError> {
    let mut new_pool_info = pool_info.clone();
    new_pool_info.last_update_block = T::BlockNumberProvider::current_block_number();
    new_pool_info.reward_per_token_stored = reward_per_token;
    Ok(new_pool_info)
}
``` [2](#0-1) 

Every state-mutating entry point calls this path via `update_pool_and_staker_rewards` (used by `stake`, `unstake`, `harvest_rewards`) or directly (`set_pool_reward_rate_per_block`, `set_pool_expiry_block`): [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

**Root cause / sequence:**
1. Pool has `expiry_block = E`, has staked tokens (`total_tokens_staked > 0`).
2. Any real (state-persisting) pool call happens at block `B1 > E` (the pool has already expired — this is explicitly permitted: `unstake`/`harvest_rewards` allow any caller once `now > pool_info.expiry_block`, see line 526/580). This call succeeds because `last_update_block` before this call was `≤ E`, so the subtraction is non-negative. But `update_pool_rewards` now writes `last_update_block = B1` (unclamped, `> E`).
3. At any later block `B2 > B1` (expiry not further extended), any subsequent state-mutating call (a different staker's `harvest_rewards`, the same staker's `unstake` to withdraw remaining principal, or the admin trying to `set_pool_expiry_block`/`set_pool_reward_rate_per_block`) invokes `reward_per_token()`, which computes `last_block_reward_applicable(E) = min(B2, E) = E`, then `E.ensure_sub(B1)`. Since `B1 > E`, this underflows and returns `Err(ArithmeticError::Underflow)`, aborting the whole extrinsic.

From that point on, **every** subsequent `stake`/`unstake`/`harvest_rewards`/admin call on that pool fails identically, because each failed attempt does not persist any state change (transactional dispatch), so `last_update_block` remains stuck at `B1 > E` forever.

### Impact Explanation
Because `unstake` and `harvest_rewards` are exactly the entry points a user needs to reclaim frozen/staked tokens and pending rewards after a pool's incentive period ends, and both routes are permanently blocked once triggered, this results in **irreversible freezing of user funds** (staked asset frozen via `T::AssetsFreezer`, and any accrued but unharvested `reward_asset_id` balance) with no available extrinsic to recover them — there is no `force_unstake` or governance bypass in this pallet's call set. Per the scan's severity guidance this is a deterministic, irreversible freezing condition, not a low/medium fee-revert as in the original Sherlock finding.

### Likelihood Explanation
No privileged role, governance, or malicious peer is required. Any ordinary account can trigger the vulnerable state simply by calling `unstake` or `harvest_rewards` (both explicitly permitted for "any account" once `now > expiry_block`) once after a pool naturally expires, which is a completely normal, expected lifecycle event for every asset-rewards pool once its `expiry_block` passes and it isn't further extended in the same call. Given pools are commonly left to reach `expiry_block` (that is the intended lifecycle, per the pallet's own `cleanup_pool` design), this is highly likely to occur in practice for any long-lived pool with even one straggling staker.

### Recommendation
In `update_pool_rewards`, persist `last_update_block` as `Self::last_block_reward_applicable(pool_info.expiry_block)` (clamped) rather than the raw current block number, so it never exceeds `expiry_block`. Alternatively/additionally, replace the `ensure_sub` in `reward_per_token()` with `saturating_sub` (treating no further elapsed reward as zero) as a defense-in-depth measure, mirroring the `defensive_saturating_sub` pattern already used for the analogous accumulator delta in `pallet-nomination-pools`'s `pending_rewards`. [9](#0-8) 

### Proof of Concept
Concrete reproduction outline (could not be executed in this session — no terminal/test-runner tool was available to me in ask-only mode; this is a code-level trace, not a confirmed test run):

```rust
// Using the pallet's own mock/test harness (substrate/frame/asset-rewards/src/mock.rs, tests.rs)
// 1. create_pool with expiry_block = 25, reward_rate_per_block = 100 (as in existing test fixtures)
// 2. staker1 and staker2 stake tokens (System::set_block_number + StakingRewards::stake)
// 3. System::set_block_number(30); // now > expiry (25)
//    assert_ok!(StakingRewards::harvest_rewards(RuntimeOrigin::signed(staker2), pool_id, None));
//    // succeeds; internally sets Pools[pool_id].last_update_block = 30 (> expiry_block 25)
// 4. System::set_block_number(40); // still no expiry extension
//    assert_noop!(
//        StakingRewards::unstake(RuntimeOrigin::signed(staker1), pool_id, amount, None),
//        ArithmeticError::Underflow // expected failure per this analysis
//    );
// 5. Any further stake/unstake/harvest_rewards call from any account on pool_id
//    fails identically and forever, since last_update_block is never corrected.
```

Failed guard: `ensure_sub` at `substrate/frame/asset-rewards/src/lib.rs:796` (`Self::last_block_reward_applicable(pool_info.expiry_block).ensure_sub(pool_info.last_update_block)?`). Deployment evidence: this is production pallet code shipped as `pallet-asset-rewards` in the scanned `polkadot-sdk` tree; I did not confirm whether/where this pallet is enabled in a live Parity/Snowbridge bounty-eligible runtime — that must be checked against the bounty's affected-version list before treating this as bounty-eligible, per the scan's instructions (file-list membership alone is not sufficient proof of eligibility). PoC execution status: **not run** — I only performed static code tracing; a background Devin session with terminal access would be required to actually execute the above `cargo test` steps against `substrate/frame/asset-rewards` and confirm the `ArithmeticError::Underflow` dispatch failure.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L513-560)
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

			// Update PoolStakers.
			staker_info.amount.ensure_sub_assign(amount)?;

			if staker_info.amount.is_zero() && staker_info.rewards.is_zero() {
				PoolStakers::<T>::remove(&pool_id, &staker);
			} else {
				PoolStakers::<T>::insert(&pool_id, &staker, staker_info);
			}

			// Emit event.
			Self::deposit_event(Event::Unstaked { caller, staker, pool_id, amount });

			Ok(())
		}
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L568-615)
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

			// Transfer unclaimed rewards from the pool to the staker.
			T::Assets::transfer(
				pool_info.reward_asset_id,
				&pool_info.account,
				&staker,
				staker_info.rewards,
				// Could kill the account, but only if the pool was already almost empty.
				Preservation::Expendable,
			)?;

			// Emit event.
			Self::deposit_event(Event::RewardsHarvested {
				caller,
				staker: staker.clone(),
				pool_id,
				amount: staker_info.rewards,
			});

			// Reset staker rewards.
			staker_info.rewards = 0u32.into();

			if staker_info.amount.is_zero() {
				PoolStakers::<T>::remove(&pool_id, &staker);
			} else {
				PoolStakers::<T>::insert(&pool_id, &staker, staker_info);
			}

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

**File:** substrate/frame/nomination-pools/src/lib.rs (L556-558)
```rust
		(current_reward_counter.defensive_saturating_sub(self.last_recorded_reward_counter))
			.checked_mul_int(self.active_points())
			.ok_or(Error::<T>::OverflowRisk)
```
