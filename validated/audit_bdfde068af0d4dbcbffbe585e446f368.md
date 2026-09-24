### Title
Truncation of `reward_per_token` in `pallet-asset-rewards` permanently destroys staker rewards for high-decimal staked assets / low reward rates - ([File: substrate/frame/asset-rewards/src/lib.rs])

### Summary
`pallet-asset-rewards` (deployed on Asset Hub Rococo/Westend and the staking-async parachain runtime) computes `reward_per_token` using a fixed multiplier `PRECISION_SCALING_FACTOR = 4096` and then permanently overwrites `reward_per_token_stored` with the truncated result, with no remainder-carry mechanism. This is the same class of integer-truncation reward-loss bug as the referenced Reserve Protocol M-04 finding, but here it is not mitigated at all: unlike the report's PR #896 mitigation (rolling remainder into the next `_claimAndSyncRewards()` call) or Substrate's `nomination-pools` pallet (which uses a `FixedU128` reward counter scaled by 10^18), this pallet's precision constant is only 4096 (2^12), several orders of magnitude smaller. For pools where staked-asset decimals are large (e.g. 18) relative to the reward rate, `reward_per_token` truncates to zero every update and the corresponding reward share is permanently lost, not merely delayed.

### Finding Description
`reward_per_token()` computes: [1](#0-0) 

```
reward_per_token_stored + reward_rate_per_block * rewardable_blocks_elapsed * PRECISION_SCALING_FACTOR / total_tokens_staked
```

with `PRECISION_SCALING_FACTOR` defined as: [2](#0-1) 

The result is written back unconditionally via `update_pool_rewards`, which fully replaces `reward_per_token_stored` with the newly computed (already-truncated) value: [3](#0-2) 

There is no accumulator that preserves the truncated remainder of `reward_rate_per_block * rewardable_blocks_elapsed * PRECISION_SCALING_FACTOR` for future incorporation (contrast with the Reserve Protocol PR #896 mitigation, which explicitly keeps unconsumed remainders for the next sync). Every call to `stake`, `unstake`, or `harvest_rewards` triggers `update_pool_and_staker_rewards` → `reward_per_token()` → `update_pool_rewards()`: [4](#0-3) [5](#0-4) 

Whenever `reward_rate_per_block.ensure_mul(rewardable_blocks_elapsed).ensure_mul(4096)` is smaller than `total_tokens_staked`, the division `.ensure_div(total_tokens_staked)` truncates to `0`, and because the pool's `reward_per_token_stored` is overwritten (not incremented from an un-truncated running total), the fractional reward for that interval vanishes forever rather than accumulating toward a future non-zero increment.

This is directly analogous to the PoC in the external report: with an 18-decimal staked asset and any realistic `reward_rate_per_block` (a reward token quantity per ~6-second block), `total_tokens_staked` for a modestly sized pool (e.g. 10^6 tokens × 10^18 = 10^24) easily dwarfs `reward_rate_per_block * 4096`, producing systematic zero increments on every interaction (`stake`/`unstake`/`harvest_rewards`), each of which independently calls `update_pool_and_staker_rewards` and stamps `last_update_block` forward — discarding the elapsed-blocks' reward entirely instead of rolling it forward.

### Impact Explanation
Stakers permanently lose a portion (potentially the entirety, in adversarial-but-realistic parameterizations) of the rewards they are economically entitled to, because the truncated remainder is never recovered. Since any signed user's own `stake`, `unstake`, or `harvest_rewards` extrinsic (or another account's `unstake`/`harvest_rewards` call on their behalf after pool expiry) triggers the `update_pool_and_staker_rewards` recomputation and stamps forward `last_update_block`, frequent pool interaction (by any of the pool's participants, not just the affected staker) compounds the loss across all stakers in the pool. This matches the "Medium" severity class of the referenced finding: a systemic accounting/rounding defect that unfairly disadvantages users without requiring a privileged attacker, but it does not constitute outright theft or unbacked issuance.

### Likelihood Explanation
This is a design defect reachable in normal operation, not requiring a privileged role, forged proof, or malicious peer — it manifests whenever a pool is configured with a staked asset that has non-trivial decimals (18 is standard for many fungible tokens) and a reward rate that is small relative to the scaled total stake, which is a common and unremarkable pool configuration rather than an edge case. `pallet-asset-rewards` is compiled into live runtimes (`asset-hub-rococo`, `asset-hub-westend`, and the `staking-async` parachain runtime) per repository wiring [6](#0-5) , though pool creation is gated by `T::CreatePoolOrigin`, meaning exploitation/discovery requires a pool with realistic parameters, which pool admins (not the affected stakers) control. I was not able to fully verify the exact `CreatePoolOrigin` configuration used on Asset Hub Rococo/Westend/staking-async parachain (i.e., whether it is permissionless or governance-gated) within the remaining investigation budget; this materially affects whether ordinary users can create adversarial pools themselves or whether they are only passive victims of pool-creator misconfiguration.

### Recommendation
Increase `PRECISION_SCALING_FACTOR` (e.g. to 10^18 as used by `nomination-pools`' `FixedU128` reward counter) and/or track/accumulate the truncated remainder of the numerator (`reward_rate_per_block * rewardable_blocks_elapsed * PRECISION_SCALING_FACTOR`) across calls to `reward_per_token()`/`update_pool_rewards()` so unconsumed fractional reward-per-token is carried forward and eventually converted into a non-zero increment, mirroring the mitigation approach referenced in the external report.

### Proof of Concept
No executable Rust/FRAME integration test was run against this repository within the scope of this investigation; the analysis is based on static code tracing of `reward_per_token()` (substrate/frame/asset-rewards/src/lib.rs:786-810), `update_pool_rewards()` (lib.rs:775-784), and the `stake`/`unstake`/`harvest_rewards` extrinsics (lib.rs:469-601), demonstrating the arithmetic truncation path is reachable through ordinary signed extrinsics with realistic pool parameters (18-decimal staked asset, modest reward rate, `PRECISION_SCALING_FACTOR = 4096`). A concrete numeric PoC analogous to the external report's scenario (`total_tokens_staked = 10^24`, `reward_rate_per_block * elapsed_blocks ≈ 10^12`, scaled result `4096 * 10^12 = 4.096 * 10^15 < 10^24` → division truncates to `0`) was derived analytically but not executed against a live/mock runtime; a background engineer with test-harness access should implement a `#[test]` in `substrate/frame/asset-rewards/src/tests.rs` reproducing this scenario to obtain empirical confirmation of permanent reward loss (as opposed to delay), and to determine the actual `CreatePoolOrigin` configuration on the affected production runtimes to assess reachability by non-privileged accounts.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L117-118)
```rust
/// Multiplier to maintain precision when calculating rewards.
pub(crate) const PRECISION_SCALING_FACTOR: u16 = 4096;
```

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

**File:** substrate/frame/asset-rewards/src/lib.rs (L562-601)
```rust
		/// Harvest unclaimed pool rewards.
		///
		/// Parameters:
		/// - origin: must be the `staker` if the pool is still active. Otherwise, any account.
		/// - pool_id: the pool to harvest from.
		/// - staker: the account for which to harvest rewards. If `None`, the caller is used.
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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L1-1)
```rust
// Copyright (C) Parity Technologies (UK) Ltd.
```
