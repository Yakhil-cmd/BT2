No vulnerability found for this question.

The reported issue requires a privileged "vault owner" to call an admin-only setter (`setInits`) to front-run the first depositor and manipulate the mint price — this is exactly the class of finding the scan rules exclude ("privileged prerequisites, pure front-running/economic attacks"). I looked for a genuine, permissionless FRAME analog anyway (any place where a privileged role can set an initial price/ratio parameter right before an unprivileged user's first deposit) and found none that matches:

- `pallet-asset-conversion`'s first-liquidity-provision path computes LP tokens purely from the caller-supplied amounts via `calc_lp_amount_for_zero_supply` (`sqrt(amount1*amount2) - MintMinLiquidity`), with no owner-settable multiplier analogous to `init0`/`init1` that could be changed between a user's submission and inclusion. [1](#0-0) [2](#0-1) 

- `pallet-nomination-pools`'s pool creation (`do_create`) always issues points to the depositor at a fixed 1:1 ratio (`POINTS_TO_BALANCE_INIT_RATIO`), with no admin-controlled parameter that could be modified pre-first-bond to skew the price a joining member pays. [3](#0-2) [4](#0-3) 

Neither pallet has a construct equivalent to Arrakis's `setInits()` (an owner-only function that can retroactively change the pricing basis for an already-pending, unprivileged first-mint transaction). Since the underlying root cause here is privileged-actor front-running of an economic parameter — explicitly out of scope — there is no qualifying Polkadot SDK analog to report.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L858-877)
```rust
			let total_supply = T::PoolAssets::total_issuance(pool.lp_token.clone());

			let lp_token_amount: T::Balance;
			if total_supply.is_zero() {
				lp_token_amount = Self::calc_lp_amount_for_zero_supply(&amount1, &amount2)?;
				T::PoolAssets::mint_into(
					pool.lp_token.clone(),
					&pool_account,
					T::MintMinLiquidity::get(),
				)?;
			} else {
				let side1 = Self::mul_div(&amount1, &total_supply, &reserve1)?;
				let side2 = Self::mul_div(&amount2, &total_supply, &reserve2)?;
				lp_token_amount = side1.min(side2);
			}

			ensure!(
				lp_token_amount > T::MintMinLiquidity::get(),
				Error::<T>::InsufficientLiquidityMinted
			);
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1353-1368)
```rust
		pub(super) fn calc_lp_amount_for_zero_supply(
			amount1: &T::Balance,
			amount2: &T::Balance,
		) -> Result<T::Balance, Error<T>> {
			let amount1 = T::HigherPrecisionBalance::from(*amount1);
			let amount2 = T::HigherPrecisionBalance::from(*amount2);

			let result = amount1
				.checked_mul(&amount2)
				.ok_or(Error::<T>::Overflow)?
				.integer_sqrt()
				.checked_sub(&T::MintMinLiquidity::get().into())
				.ok_or(Error::<T>::InsufficientLiquidityMinted)?;

			result.try_into().map_err(|_| Error::<T>::Overflow)
		}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L248-256)
```rust
//! To achieve this, we issue points based on the following:
//!
//! ```text
//! points_issued = (points_before_transfer / balance_before_transfer) * amount_transferred;
//! ```
//!
//! For new bonded pools we can set the points issued per balance arbitrarily. In this
//! implementation we use a 1 points to 1 balance ratio for pool creation (see
//! [`POINTS_TO_BALANCE_INIT_RATIO`]).
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3573-3606)
```rust
	fn do_create(
		who: T::AccountId,
		amount: BalanceOf<T>,
		root: AccountIdLookupOf<T>,
		nominator: AccountIdLookupOf<T>,
		bouncer: AccountIdLookupOf<T>,
		pool_id: PoolId,
	) -> DispatchResult {
		// ensure depositor is not restricted from joining the pool.
		ensure!(!T::Filter::contains(&who), Error::<T>::Restricted);

		let root = T::Lookup::lookup(root)?;
		let nominator = T::Lookup::lookup(nominator)?;
		let bouncer = T::Lookup::lookup(bouncer)?;

		ensure!(amount >= Pallet::<T>::depositor_min_bond(), Error::<T>::MinimumBondNotMet);
		ensure!(
			MaxPools::<T>::get().map_or(true, |max_pools| BondedPools::<T>::count() < max_pools),
			Error::<T>::MaxPools
		);
		ensure!(!PoolMembers::<T>::contains_key(&who), Error::<T>::AccountBelongsToOtherPool);
		let mut bonded_pool = BondedPool::<T>::new(
			pool_id,
			PoolRoles {
				root: Some(root),
				nominator: Some(nominator),
				bouncer: Some(bouncer),
				depositor: who.clone(),
			},
		);

		bonded_pool.try_inc_members()?;
		let points = bonded_pool.try_bond_funds(&who, amount, BondType::Create)?;

```
