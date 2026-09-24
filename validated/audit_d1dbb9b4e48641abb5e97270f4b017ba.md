### Title
Permanent DOS / fund lock in `pallet-asset-rewards` due to `last_update_block` never being capped to `expiry_block`, causing arithmetic underflow in `reward_per_token` - (File: `substrate/frame/asset-rewards/src/lib.rs`)

### Summary
`pallet-asset-rewards`'s reward accounting stores `PoolInfo::last_update_block`, which every reward-touching extrinsic sets to the *current* block number, without ever capping it to `PoolInfo::expiry_block`. Once a pool has passed its `expiry_block` and any ordinary, unprivileged staker calls `stake` (which has no expiry guard) — or any other reward-updating call — `last_update_block` becomes greater than `expiry_block`. Every subsequent reward computation calls `last_block_reward_applicable(expiry_block).ensure_sub(last_update_block)`, which now underflows and returns an `ArithmeticError`, causing `stake`, `unstake`, `harvest_rewards`, `set_pool_reward_rate_per_block` **and even `set_pool_expiry_block`** (the only function that could otherwise fix the situation, since it also calls `reward_per_token` first) to permanently fail for that pool. This locks all staked/reward funds in the pool.

### Finding Description
`reward_per_token` computes elapsed blocks as: [1](#0-0) 

`last_block_reward_applicable` caps the "now" side at `expiry_block`, but nothing caps `last_update_block`: [2](#0-1) 

`update_pool_rewards`, called by every reward-touching extrinsic, unconditionally sets `last_update_block` to the current block, with no bound relative to `expiry_block`: [3](#0-2) 

Crucially, `stake` has **no expiry check at all** — unlike `unstake`/`harvest_rewards`, which at least gate non-owner calls (`caller == staker` bypass) but still permit the staker themselves to act after expiry: [4](#0-3) [5](#0-4) 

Sequence to reach the DOS state (all callable by an ordinary, unprivileged staker with an active position, no governance/root needed):
1. Pool `P` has `expiry_block = E`, `total_tokens_staked > 0`. `last_update_block <= E` (invariant holds while pool active).
2. At block `now1 > E` (pool naturally expired), any staker calls `stake(pool_id, amount)` (adding more stake, or `harvest_rewards`/`unstake` on themselves). `reward_per_token` succeeds this first time because `last_block_reward_applicable(E) = E >= last_update_block` (old value, still `<= E`). `update_pool_rewards` then sets `last_update_block = now1` (unbounded), which is now `> E`. This call **succeeds** and silently poisons the pool state.
3. Any subsequent call touching this pool (`stake`, `unstake`, `harvest_rewards`, `set_pool_reward_rate_per_block`) calls `reward_per_token` again: `last_block_reward_applicable(E) = E` (since `now2 > E`), and `E.ensure_sub(now1)` underflows because `now1 > E`. `ensure_sub` returns an `ArithmeticError`, and the whole extrinsic fails.
4. Even the pool admin's only theoretically-available remedy, `set_pool_expiry_block`, first calls `reward_per_token` before applying the new expiry: [6](#0-5) 
   This call **also fails with the same underflow**, so the admin cannot rescue the pool either.

This exactly mirrors the reported bug class: an accumulator/checkpoint value (`assetState_.lastRewardGlobal` in the report, `last_update_block` here) is advanced by a state-mutating entry point that lacks the same boundary check as sibling functions (report: `mint`/`increaseLiquidity` vs `decreaseLiquidity`/`claimReward`; here: `stake` vs `unstake`/`harvest_rewards`, though even the latter two are insufficiently guarded since the staker themselves can trigger the poisoning call). Once poisoned, every function relying on the subtraction reverts, permanently, locking funds — no privileged role, no stolen keys, no forged input is used; the attacker (or an ordinary careless user) is only exercising normal, permitted extrinsics (`stake`) after a pool's natural expiry.

### Impact Explanation
Once poisoned, `stake`, `unstake`, `harvest_rewards`, and `set_pool_reward_rate_per_block` all permanently revert for the affected pool, and the admin's `set_pool_expiry_block` rescue path also reverts. Staked tokens (frozen via `T::AssetsFreezer`) and any accrued but unharvested rewards become permanently unrecoverable through normal pallet extrinsics — an irreversible freezing of user funds, triggerable by any unprivileged staker's ordinary usage after a pool expires. `pallet-asset-rewards` is wired into at least the AssetHub Westend runtime (governance-created pools, e.g. treasury-funded reward pools), so this is a real runtime-reachable path, not merely a dependency/pallet-only construct.

### Likelihood Explanation
High. It requires only an already-existing, expired pool with active stakers (a normal end-of-life state for any time-bounded incentive pool) and a single ordinary `stake` call by any staker after `expiry_block` has passed — no governance, no privileged origin, no malicious peer, and no unusual input crafting. This is a natural usage pattern (a staker topping up their stake, unaware the pool just expired) rather than a contrived exploit, making accidental or intentional triggering equally easy.

### Recommendation
Cap `last_update_block` to `expiry_block` in `update_pool_rewards` (i.e., `new_pool_info.last_update_block = last_block_reward_applicable(pool_info.expiry_block).min(current_block_number())`, or simply always store `last_block_reward_applicable(expiry_block)` when past expiry), analogous to using `min(now, expiry)` consistently on both sides of the subtraction. Additionally, consider rejecting `stake` calls on already-expired pools, mirroring the intent already present (but insufficiently enforced) in `unstake`/`harvest_rewards`. Use `saturating_sub`/`defensive_saturating_sub` as a defense-in-depth guard in `reward_per_token` so a boundary-condition bug degrades to "zero elapsed blocks" rather than a permanent, unrecoverable `DispatchError`.

### Proof of Concept
No test execution tools were available in this session; the trace above is derived directly from reading `substrate/frame/asset-rewards/src/lib.rs` (functions `reward_per_token`, `update_pool_rewards`, `last_block_reward_applicable`, `stake`, `unstake`, `harvest_rewards`, `set_pool_expiry_block`) and confirming the missing expiry guard on `stake`, the unconditional assignment in `update_pool_rewards`, and that `set_pool_expiry_block` itself depends on `reward_per_token` succeeding first — so it cannot self-heal. This has not been run against the pallet's existing test harness (`substrate/frame/asset-rewards/src/tests.rs`); a concrete Rust unit test would: create a pool with a short `expiry_block`, `stake` before expiry, advance the block number past `expiry_block`, call `stake` again (poisoning `last_update_block`), advance one more block, and then assert that a subsequent `unstake`/`harvest_rewards`/`set_pool_reward_rate_per_block`/`set_pool_expiry_block` call returns `Err(ArithmeticError::Underflow)` (or the pallet's mapped error), demonstrating the permanent lock. This should be executed and confirmed by a maintainer/agent with local build/test access before triage.

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

**File:** substrate/frame/asset-rewards/src/lib.rs (L794-801)
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
