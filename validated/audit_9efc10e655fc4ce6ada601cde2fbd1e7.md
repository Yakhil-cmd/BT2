No vulnerability found for this question.

The reported issue concerns Solidity `Gauge`/`CLGauge`/`Bribes` contracts (an AMM voting-incentive design) where `notifyRewardAmount` can pre-fund a reward epoch whose total supply turns out to be zero, permanently locking those tokens because the contracts have no rescue function. This is a Solidity-specific accounting pattern that does not map cleanly onto FRAME.

The closest functional analog in this codebase is `pallet-asset-rewards`, which implements a similar Synthetix-style reward-per-token accrual model [1](#0-0) . Unlike the Solidity contracts, this pallet computes rewards just-in-time from `reward_rate_per_block` and `total_tokens_staked`, and explicitly guards against the zero-total-supply case by returning the stored `reward_per_token` unchanged when `total_tokens_staked` is zero, rather than accruing and losing rewards [2](#0-1) . Because rewards aren't pre-transferred per epoch the way `notifyRewardAmount` does, no funds become stranded due to a zero-supply window in the same way.

Furthermore, this pallet already provides an explicit rescue path: `cleanup_pool`, callable by the pool admin once there are no remaining stakers, transfers any leftover reward-asset balance in the pool account back to the admin and removes the pool storage [3](#0-2) . This is functionally the "add functionality to rescue the rewards" recommendation from the report, already implemented.

I also checked other reward-distribution pallets (`pallet-staking-async`, `pallet-election-provider-multi-block`'s signed-phase reward source, `pallet-nomination-pools`) for a similar "funds permanently stuck due to zero total stake with no rescue" pattern, and none exhibit an unrescuable stuck-funds condition analogous to the reported Solidity bug — e.g., `pallet-election-provider-multi-block` even added a `claim_unpaid_reward` mechanism specifically to avoid rewards being silently lost when a payout source is depleted [4](#0-3) .

Since no FRAME entry point demonstrates the same "zero total supply → permanently stuck rewards with no rescue" defect via a real signed-extrinsic path, this does not have a demonstrable Polkadot SDK analog.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L65-71)
```rust
//! ## Rewards Algorithm
//!
//! The rewards algorithm is based on the Synthetix [StakingRewards.sol](https://web.archive.org/web/20251223190741/https://github.com/Synthetixio/synthetix/blob/develop/contracts/StakingRewards.sol)
//! smart contract.
//!
//! Rewards are calculated JIT (just-in-time), and all operations are O(1) making the approach
//! scalable to many pools and stakers.
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L690-729)
```rust
		/// Cleanup a pool.
		///
		/// Origin must be the pool admin.
		///
		/// Cleanup storage, release any associated storage cost and return the remaining reward
		/// tokens to the admin.
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

**File:** substrate/frame/asset-rewards/src/lib.rs (L787-810)
```rust
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

**File:** substrate/frame/election-provider-multi-block/src/signed/mod.rs (L1089-1110)
```rust
		/// Pay out a round's [`UnpaidRewards`] entry to its winner. Permissionless: anyone may
		/// call it for any round. Free on success, normal fee on failure to discourage spam.
		#[pallet::call_index(5)]
		#[pallet::weight(SignedWeightsOf::<T>::claim_unpaid_reward())]
		pub fn claim_unpaid_reward(origin: OriginFor<T>, round: u32) -> DispatchResultWithPostInfo {
			let _ = ensure_signed(origin)?;
			let mut unpaid = UnpaidRewards::<T>::get();
			let idx = unpaid
				.iter()
				.position(|entry| entry.round == round)
				.ok_or(Error::<T>::NoUnpaidReward)?;
			let entry = unpaid[idx].clone();

			Self::transfer_or_mint(&entry.who, entry.amount)
				.map_err(|_| Error::<T>::PotStillDepleted)?;

			unpaid.remove(idx);
			UnpaidRewards::<T>::put(unpaid);
			Self::deposit_event(Event::<T>::Rewarded(entry.round, entry.who, entry.amount));

			Ok(Pays::No.into())
		}
```
