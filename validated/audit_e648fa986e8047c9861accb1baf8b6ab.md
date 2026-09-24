### Title
Unbounded `last_update_block` corrupts `reward_per_token()` after pool expiry, permanently freezing staked funds - (File: `substrate/frame/asset-rewards/src/lib.rs`)

### Summary
`pallet-asset-rewards`'s `update_pool_rewards` unconditionally sets `PoolInfo::last_update_block` to the current block number, without capping it at `expiry_block`. Once a pool has expired and any account interacts with it (a normal, permissionless `stake` call), `last_update_block` gets set to a value **past** `expiry_block`. On the very next interaction, `reward_per_token()` computes `last_block_reward_applicable(expiry_block).ensure_sub(last_update_block)`, which now underflows (`expiry_block < last_update_block`), causing the call to fail. Because every mutating pool interaction (`stake`, `unstake`, `harvest_rewards`) must first pass through this calculation, and a failed extrinsic never persists the corrupted-but-not-yet-broken state, the pool becomes permanently stuck in a state where **all** future interactions fail — freezing already-staked (frozen) tokens forever with no recovery path.

### Finding Description
`PoolInfo::last_update_block` is meant to track the block up to which rewards were already accounted for, and must never exceed `expiry_block` (rewards stop accruing at expiry). The reward math enforces this cap only on the *read* side via `last_block_reward_applicable`: [1](#0-0) 

but the *write* side, `update_pool_rewards`, does not apply the same cap: [2](#0-1) 

`reward_per_token()` then subtracts the stored `last_update_block` from the capped "now": [3](#0-2) 

`stake()` is a plain signed extrinsic with **no expiry check at all**, so any account can call it even after `expiry_block` has passed: [4](#0-3) 

Exploit sequence (attacker has no privileged role — this is a normal user interaction pattern, not an attack requiring special access):
1. `create_pool` with `expiry_block = E` (any account with `CreatePoolOrigin`, or a normal user staking into an existing pool).
2. At `t0 < E`, staker A calls `stake(pool_id, X)`. Since `total_tokens_staked` was `0`, `reward_per_token` short-circuits and returns early; `update_pool_rewards` sets `last_update_block = t0` (valid, `t0 < E`).
3. Time passes; nobody interacts with the pool until `t1 > E` (expiry has passed).
4. At `t1 > E`, staker A calls `stake(pool_id, Y)` again. Now `total_tokens_staked = X != 0`, so `reward_per_token` computes `last_block_reward_applicable(E) - last_update_block = E - t0` (still valid, succeeds). `update_pool_rewards` then sets `last_update_block = current_block_number() = t1`, which is **now greater than `expiry_block`**. This is persisted to storage via `Pools::<T>::insert`.
5. At `t2 >= t1`, staker A calls `unstake`, `harvest_rewards`, or `stake` again. `reward_per_token` computes `last_block_reward_applicable(E) - last_update_block = E - t1`, and since `t1 > E`, this is a subtraction of a larger value from a smaller one on an unsigned `BlockNumber` — `ensure_sub` returns `Err(ArithmeticError::Underflow)`, and the whole extrinsic fails.
6. Because the extrinsic fails, storage is never updated, so `last_update_block` remains permanently stuck at `t1 > E`. **Every subsequent call to `stake`, `unstake`, or `harvest_rewards` for this pool will hit the exact same underflow and fail**, forever.

Unlike the Solidity report where the failure mode is a low-level panic revert, here `ensure_sub` returns a graceful `DispatchError`, but the practical effect is identical: the corrupted `last_update_block` can never self-heal (there is no path that resets it below `expiry_block` once broken), so the pool and every staker's frozen tokens (frozen via `T::AssetsFreezer` in `stake`) and unclaimed rewards become permanently inaccessible.

### Impact Explanation
This is an irreversible freezing of user funds: staked tokens are held under a `FreezeReason::Staked` freeze via `T::AssetsFreezer::increase_frozen` in `stake()`, and can only be released through `unstake()`, which is now permanently broken for the affected pool. `harvest_rewards()` is equally broken. There is no admin recovery function that can reset `last_update_block` (the admin-facing `set_pool_reward_rate_per_block` and `set_pool_expiry_block` both go through the same broken `update_pool_rewards`/`reward_per_token` path and would also fail once corrupted). The only workaround (`cleanup_pool`) requires the pool to have zero stakers, which is unreachable since `unstake` is broken. This matches the "irreversible freezing" category the analog rules prioritize as High/Critical.

### Likelihood Explanation
Requires no privileged role, no malicious validator/collator, and no governance action — just two ordinary signed calls to `stake` from a permissionless staker, one of which naturally happens after the pool's `expiry_block` (which is entirely plausible in normal usage, since nothing prevents `stake()` from being called on an expired pool, and pool expiry timing is public and predictable). The only precondition is that the pool had non-zero `total_tokens_staked` before expiry (from any prior stake) and that at least one interaction occurs after expiry before any admin extends `expiry_block`. This is a highly likely, low-cost, deterministic sequence.

### Recommendation
Cap `last_update_block` at `expiry_block` in `update_pool_rewards`, mirroring `last_block_reward_applicable`:
```rust
new_pool_info.last_update_block =
    Self::last_block_reward_applicable(pool_info.expiry_block);
```
This keeps the invariant `last_update_block <= expiry_block` intact at all times, preventing the underflow in `reward_per_token` and preserving the ability to `unstake`/`harvest_rewards` after expiry.

### Proof of Concept
Failed guards / verified facts:
- `stake()` at [4](#0-3)  has no `expiry_block` check, confirmed by direct reading — any signed account can stake post-expiry.
- `update_pool_rewards` unconditionally sets `last_update_block = current_block_number()` with no cap, confirmed at [2](#0-1) , while the read-side cap exists only in `last_block_reward_applicable` at [1](#0-0) .
- `ensure_sub` returns `ArithmeticError::Underflow` (verified in `substrate/primitives/arithmetic/src/traits.rs`), so the failure manifests as `DispatchError` rather than a panic, but is deterministic and permanent given the state corruption.

Deployment/PoC execution status: **Not executed.** I traced the logic statically across `substrate/frame/asset-rewards/src/lib.rs` and confirmed the absence of any capping/guard through direct code reading, but I did not run an actual FRAME test (e.g., adding a test to `substrate/frame/asset-rewards/src/tests.rs` using its existing mock `BlockNumberProvider`/`System::set_block_number` harness) to empirically confirm the underflow triggers `Err` at runtime. A concrete reproduction would extend the existing test module with: create pool (`expiry_block = 10`), `stake(1, 10, 100)` at block 1, advance to block 20, `stake(1, 10, 50)` (this stores `last_update_block = 20 > 10`), advance to block 21, then call `unstake`/`harvest_rewards`/`stake` again and assert it returns `Err(ArithmeticError::Underflow.into())`. I was not able to fully inspect `substrate/frame/asset-rewards/src/mock.rs` and `tests.rs` contents due to iteration limits, so exact helper function names/signatures for constructing this test are not confirmed — a background engineer should adapt to the existing test helpers found in that file.

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
