### Title
Reward-per-token precision loss causes complete reward loss for stakers in `pallet-asset-rewards` when `total_tokens_staked` is large - (File: `substrate/frame/asset-rewards/src/lib.rs`)

### Summary
`pallet-asset-rewards::reward_per_token` computes a per-block reward index using a fixed scaling constant `PRECISION_SCALING_FACTOR = 4096` [1](#0-0) . Any signed account can call the permissionless `stake` extrinsic to inflate `total_tokens_staked` for a pool to an arbitrarily large value [2](#0-1) , which is the exact denominator used in the reward-per-token division. Just like the Biconomy `LiquidityFarming`/`LiquidityProviders` bug, once `reward_rate_per_block * blocks_elapsed * PRECISION_SCALING_FACTOR < total_tokens_staked`, integer division truncates the numerator to zero, and legitimate stakers permanently lose all pending rewards for that period.

### Finding Description
`reward_per_token` computes:
```
reward_per_token_stored + reward_rate_per_block * rewardable_blocks_elapsed * PRECISION_SCALING_FACTOR / total_tokens_staked
``` [3](#0-2) 

`PRECISION_SCALING_FACTOR` is a hardcoded `u16` constant equal to `4096` (2^12), an extremely small precision buffer compared to typical `1e18`/`1e36`-scale accumulators used in similar designs [1](#0-0) . `total_tokens_staked` is a `T::Balance` value that is incremented directly by attacker-controlled input in the permissionless `stake(origin, pool_id, amount)` extrinsic — any signed account can call it with an arbitrarily large `amount` (subject only to their asset balance) [2](#0-1) . There is no cap relating `total_tokens_staked` growth to the reward rate or scaling factor.

`derive_rewards`, which computes a staker's owed balance, divides again by the same `PRECISION_SCALING_FACTOR`:
```
staker.amount * (reward_per_token - staker.reward_per_token_paid) / PRECISION_SCALING_FACTOR
``` [4](#0-3) 

Because `reward_per_token` itself is truncated to zero whenever `total_tokens_staked` exceeds `reward_rate_per_block * blocks_elapsed * 4096`, the resulting `reward_per_token_stored` never advances, and `derive_rewards` yields `0` for every staker — the reward tokens accrue silently in the pool account but are never distributable via `harvest_rewards` [5](#0-4) , mirroring exactly the Biconomy `accumulator = 0` scenario in `getUpdatedAccTokenPerShare`.

This is the same root cause as the referenced report: an attacker-inflatable share/stake denominator combined with an undersized fixed-point scaling numerator in an on-chain reward accumulator, causing integer-division truncation to zero.

### Impact Explanation
Any staker (including the attacker, but critically also all *other, honest* stakers) in the affected pool permanently loses rewards accrued during any block range where the precision-loss condition holds, since `reward_per_token_stored` is monotonically non-decreasing and past truncated periods can never be recovered. Reward tokens remain stuck in the pool's reward account, effectively frozen/lost to their rightful recipients — a direct, unauthorized loss of value for pool participants, achievable by a single unprivileged account staking a large but realistic asset amount (e.g., any high-decimals/low-value asset scaled similarly to the Biconomy LP-share example, `1e44`-magnitude values are trivially reachable with 18-decimal fungible assets and normal `u128`/custom `Balance` types). This qualifies as High severity, matching the original finding's severity determination.

### Likelihood Explanation
Likelihood is high in practice for pools using assets with many decimals or reward rates that are small relative to typical staking amounts, since `PRECISION_SCALING_FACTOR` is a fixed constant (`4096`) independent of the asset's decimal precision or the configured `reward_rate_per_block`. No governance, privileged role, or malicious validator/collaborator is required — the `stake` extrinsic is open to any signed account under normal permissions [6](#0-5) , and a whale staker (or even the aggregate of many depositors) reaching the threshold is a realistic, low-cost operation, not an unbounded-loop/storage-growth or purely economic attack — it is a direct arithmetic truncation bug reachable via normal usage.

### Recommendation
- Increase `PRECISION_SCALING_FACTOR` substantially (e.g., to `10^18` or larger, matching `Balance` precision), or switch the accumulator to a proper fixed-point type (e.g., `FixedU128`/`U256` intermediate as done in `pallet-nomination-pools`'s `RewardCounter`/`checked_from_rational` approach) rather than a raw `u16` constant with integer division [7](#0-6) .
- Alternatively, compute `reward_per_token` using widened arithmetic (`U256`) prior to scaling/dividing, as `pallet-nomination-pools`'s `balance_to_point`/`point_to_balance` do via `T::BalanceToU256`/`T::U256ToBalance` [8](#0-7) , to avoid premature truncation.
- Add a sanity/documentation-enforced bound or runtime check ensuring `reward_rate_per_block * PRECISION_SCALING_FACTOR` remains large relative to expected `total_tokens_staked` for the configured asset's decimals, or reject/alert when `reward_per_token` would compute to a non-increasing value while non-zero rewards are pending.

### Proof of Concept
Not executed against a live network; this is a static code-level analysis derived from reading `substrate/frame/asset-rewards/src/lib.rs`. A minimal reproduction path (not run here) would be:
1. `create_pool` (permissioned call, but pool existence itself is not the vulnerability — only used to set up the scenario) with a modest `reward_rate_per_block`.
2. Attacker/staker calls `stake(origin, pool_id, amount)` with `amount` large enough that `total_tokens_staked > reward_rate_per_block * blocks_elapsed * 4096` for a realistic number of elapsed blocks.
3. Call `update_pool_and_staker_rewards`/`reward_per_token` and observe `new_pending_rewards / total_tokens_staked` integer-divides to `0`, and hence `derive_rewards` returns `0` for all stakers despite non-zero elapsed reward budget [9](#0-8) .
4. `harvest_rewards` then transfers `0` to the staker, confirming loss of rewards that were nominally earned [5](#0-4) .

I was not able to execute this scenario in a test harness within this session; the existing `substrate/frame/asset-rewards/src/tests.rs` file (only partially inspected) should be checked for whether this large-stake precision-loss case is already covered — if not, it should be added as a regression test alongside the nomination-pools precision tests (`reward_counter_precision` module) which explicitly test this class of issue and pass, in contrast to this pallet's fixed small scaling factor [10](#0-9) .

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L117-118)
```rust
/// Multiplier to maintain precision when calculating rewards.
pub(crate) const PRECISION_SCALING_FACTOR: u16 = 4096;
```

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

**File:** substrate/frame/asset-rewards/src/lib.rs (L568-606)
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
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L786-824)
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

		/// Derives the amount of rewards earned by a staker.
		///
		/// This is a helper function for `update_pool_rewards` and should not be called directly.
		fn derive_rewards(
			staker_info: &PoolStakerInfo<T::Balance>,
			reward_per_token: &T::Balance,
		) -> Result<T::Balance, DispatchError> {
			Ok(staker_info
				.amount
				.ensure_mul(reward_per_token.ensure_sub(staker_info.reward_per_token_paid)?)?
				.ensure_div(PRECISION_SCALING_FACTOR.into())?
				.ensure_add(staker_info.rewards)?)
		}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L1506-1509)
```rust
		let current_reward_counter =
			T::RewardCounter::checked_from_rational(new_pending_rewards, bonded_points)
				.and_then(|ref r| self.last_recorded_reward_counter.checked_add(r))
				.ok_or(Error::<T>::OverflowRisk)?;
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3489-3497)
```rust
			(false, false) => {
				// Equivalent to (current_points / current_balance) * new_funds
				balance(
					u256(current_points)
						.saturating_mul(u256(new_funds))
						// We check for zero above
						.div(u256(current_balance)),
				)
			},
```

**File:** substrate/frame/nomination-pools/src/tests.rs (L5750-5821)
```rust
mod reward_counter_precision {
	use super::*;

	const DOT: Balance = 10u128.pow(10u32);
	const POLKADOT_TOTAL_ISSUANCE_GENESIS: Balance = DOT * 10u128.pow(9u32);

	const fn inflation(years: u128) -> u128 {
		let mut i = 0;
		let mut start = POLKADOT_TOTAL_ISSUANCE_GENESIS;
		while i < years {
			start = start + start / 10;
			i += 1
		}
		start
	}

	fn default_pool_reward_counter() -> FixedU128 {
		let bonded_pool = BondedPools::<T>::get(1).unwrap();
		RewardPools::<Runtime>::get(1)
			.unwrap()
			.current_reward_counter(1, bonded_pool.points, bonded_pool.commission.current())
			.unwrap()
			.0
	}

	fn pending_rewards(of: AccountId) -> Option<BalanceOf<T>> {
		let member = PoolMembers::<T>::get(of).unwrap();
		assert_eq!(member.pool_id, 1);
		let rc = default_pool_reward_counter();
		member.pending_rewards(rc).ok()
	}

	#[test]
	fn smallest_claimable_reward() {
		// create a pool that has all of the polkadot issuance in 50 years.
		let pool_bond = inflation(50);
		ExtBuilder::default().ed(DOT).min_bond(pool_bond).build_and_execute(|| {
			assert_eq!(
				pool_events_since_last_call(),
				vec![
					Event::Created { depositor: 10, pool_id: 1 },
					Event::Bonded {
						member: 10,
						pool_id: 1,
						bonded: 1173908528796953165005,
						joined: true,
					},
					Event::MetadataUpdated { pool_id: 1, caller: 900 },
				]
			);

			// the smallest reward that this pool can handle is
			let expected_smallest_reward = inflation(50) / 10u128.pow(18);

			// tad bit less. cannot be paid out.
			deposit_rewards(expected_smallest_reward - 1);
			assert_ok!(Pools::claim_payout(RuntimeOrigin::signed(10)));
			assert_eq!(pool_events_since_last_call(), vec![]);
			// revert it.

			remove_rewards(expected_smallest_reward - 1);

			// tad bit more. can be claimed.
			deposit_rewards(expected_smallest_reward + 1);
			assert_ok!(Pools::claim_payout(RuntimeOrigin::signed(10)));
			assert_eq!(
				pool_events_since_last_call(),
				vec![Event::PaidOut { member: 10, pool_id: 1, payout: 1173 }]
			);
		})
	}

```
