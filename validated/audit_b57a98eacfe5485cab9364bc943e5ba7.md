## Title
First LP griefs future LPs by self-transferring `remove_liquidity` withdrawals back into the pool account, decoupling `MintMinLiquidity` protection - (File: `substrate/frame/asset-conversion/src/lib.rs`)

## Summary
`pallet_asset_conversion::remove_liquidity` lets any signed caller specify an arbitrary `withdraw_to` account, including the pool's own derived account. Sending the withdrawn reserves back to the pool account is a self-transfer that leaves reserves unchanged while `T::PoolAssets::burn_from` still reduces the LP token's total supply. A first liquidity provider can therefore mint the minimum LP allotment, then burn almost all of it back "to itself" (the pool account), collapsing `total_supply` toward the permanently-locked `MintMinLiquidity` floor while reserves stay intact. This inflates the value-per-LP-token ratio and forces any subsequent depositor to supply amounts comparable to the *entire* existing reserve just to mint more than `MintMinLiquidity` tokens — the same "1000×-deposit-required" DoS pattern described in the DODO GSP report, reachable here via ordinary signed `add_liquidity`/`remove_liquidity` extrinsics with no privileged role.

## Finding Description
`pallet_asset_conversion` is designed to defend against the classic "donate to inflate LP-per-share" attack by permanently locking `T::MintMinLiquidity::get()` LP tokens in the pool account whenever the pool is bootstrapped from zero supply [1](#0-0) , and by requiring `lp_token_amount > T::MintMinLiquidity::get()` on every mint [2](#0-1) . The genesis mint math likewise subtracts `MintMinLiquidity` from the geometric mean of the two deposited amounts [3](#0-2) , and a dedicated test confirms this guard is enforced at pool creation [4](#0-3) .

However, `do_remove_liquidity` never verifies that `withdraw_to` differs from the pool's own derived account. It computes `amount1`/`amount2` from the burned LP proportion of the reserves, burns the caller's LP tokens, and then transfers the withdrawn amounts to whatever `withdraw_to` the caller supplied [5](#0-4) . The public extrinsic simply forwards the caller-controlled `withdraw_to` parameter with no restriction [6](#0-5) . If `withdraw_to == pool_account` (the pool's derived account, obtainable via `T::PoolLocator::address`), the `T::Assets::transfer(asset, &pool_account, withdraw_to, amount, Expendable)` calls are self-transfers that leave the pool's asset balances (i.e., `reserve1`/`reserve2`) unchanged, while `T::PoolAssets::burn_from` still permanently destroys the caller's LP tokens and reduces `total_supply`.

Because `do_add_liquidity`'s non-zero-supply mint math is `lp_token_amount = min(amount1 * total_supply / reserve1, amount2 * total_supply / reserve2)` [7](#0-6) , driving `total_supply` down toward the locked `MintMinLiquidity` floor while `reserve1`/`reserve2` stay large forces any later depositor to contribute an amount approaching the full existing reserve size just to clear the `lp_token_amount > MintMinLiquidity` check. This is functionally identical to the DODO GSP bug: the first LP sets the withdrawal recipient to the pool contract itself, burns down its own shares, and leaves the pool "reserve-heavy, share-light," forcing subsequent depositors to provide disproportionately large amounts or have their mint revert.

## Impact Explanation
Any ordinary signed account that is the first (or an early, dominant) liquidity provider of a pool can grief all future depositors on that specific asset pair pool without needing governance, privileged origins, or any external chain/consensus role — only the standard `add_liquidity`/`remove_liquidity` extrinsics exposed to any signed user. The result is a pool that is practically unusable for new LPs unless they are willing to add liquidity comparable in size to the entire existing reserve, which is a denial-of-service against normal DEX usage of `pallet_asset_conversion` (deployed in production on Asset Hub runtimes and other runtimes using this pallet, e.g. `substrate/bin/node/runtime/src/lib.rs` and `cumulus/parachains/runtimes/testing/penpal/src/lib.rs`). It does not directly mint unbacked assets or steal already-deposited funds from other accounts, so it is best characterized as a Medium-severity availability/griefing issue, matching the audited report's own Medium classification.

## Likelihood Explanation
Likelihood is high for any newly created or thinly-provisioned pool: creating a pool and being its dominant LP requires no special permission (`create_pool`/`add_liquidity` are open to all signed accounts), and nothing in `do_remove_liquidity` or the `remove_liquidity` extrinsic prevents `withdraw_to` from being the pool's own account. An attacker only needs to know the deterministic `PoolLocator::address` for the target pool, which is derivable from the pallet's public `AccountIdConverter`/`PoolLocator` types.

## Recommendation
In `do_remove_liquidity` (and consider `do_add_liquidity`'s `mint_to`), reject the operation when the caller-supplied `withdraw_to` (or `mint_to`) resolves to the pool's own derived account, e.g.:
```rust
let pool_account = T::PoolLocator::address(&pool_id).map_err(|_| Error::<T>::InvalidAssetPair)?;
ensure!(withdraw_to != &pool_account, Error::<T>::InvalidWithdrawTo);
```
This mirrors the fix recommended for the DODO GSP finding and preserves the intended invariant that burning LP tokens always corresponds to an external reduction of both `total_supply` and `reserve` in the same proportion.

## Proof of Concept
Reachable path (no privileged role, standard signed extrinsics):
1. `create_pool(asset1, asset2)` — open to any signed account [8](#0-7) .
2. `add_liquidity(asset1, asset2, amt1, amt2, ..., mint_to = attacker)` on the empty pool: mints `sqrt(amt1*amt2) - MintMinLiquidity` LP tokens to attacker and locks `MintMinLiquidity` LP tokens at the pool account [1](#0-0) .
3. Compute `pool_account = PoolLocator::address(pool_id)`.
4. `remove_liquidity(asset1, asset2, lp_token_burn = attacker_balance - 1, ..., withdraw_to = pool_account)`: burns almost all of attacker's LP tokens via `T::PoolAssets::burn_from`, but the subsequent `T::Assets::transfer(asset, &pool_account, &pool_account, amount, Expendable)` calls are self-transfers that leave `reserve1`/`reserve2` unchanged [9](#0-8) .
5. `total_supply` now sits barely above the locked `MintMinLiquidity`, while reserves remain at their original (large) size. Any new LP calling `add_liquidity` must now supply an amount approaching the full existing reserve to clear `ensure!(lp_token_amount > T::MintMinLiquidity::get(), Error::<T>::InsufficientLiquidityMinted)` [2](#0-1) , or the call fails exactly as in the referenced `add_tiny_liquidity_leads_to_insufficient_liquidity_minted_error` test pattern [4](#0-3) .

No code execution was performed against a live network in producing this analysis; the trace above is derived purely from reading the referenced production pallet source and existing unit tests that already validate the surrounding mint/burn arithmetic used in the reasoning.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L440-450)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::create_pool())]
		pub fn create_pool(
			origin: OriginFor<T>,
			asset1: Box<T::AssetKind>,
			asset2: Box<T::AssetKind>,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::do_create_pool(&sender, *asset1, *asset2, None)?;
			Ok(())
		}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L497-517)
```rust
		pub fn remove_liquidity(
			origin: OriginFor<T>,
			asset1: Box<T::AssetKind>,
			asset2: Box<T::AssetKind>,
			lp_token_burn: T::Balance,
			amount1_min_receive: T::Balance,
			amount2_min_receive: T::Balance,
			withdraw_to: T::AccountId,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::do_remove_liquidity(
				&sender,
				*asset1,
				*asset2,
				lp_token_burn,
				amount1_min_receive,
				amount2_min_receive,
				&withdraw_to,
			)?;
			Ok(())
		}
```

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

**File:** substrate/frame/asset-conversion/src/lib.rs (L894-952)
```rust
		/// Remove liquidity from a pool.
		pub(crate) fn do_remove_liquidity(
			who: &T::AccountId,
			asset1: T::AssetKind,
			asset2: T::AssetKind,
			lp_token_burn: T::Balance,
			amount1_min_receive: T::Balance,
			amount2_min_receive: T::Balance,
			withdraw_to: &T::AccountId,
		) -> Result<(T::Balance, T::Balance), DispatchError> {
			let pool_id = T::PoolLocator::pool_id(&asset1, &asset2)
				.map_err(|_| Error::<T>::InvalidAssetPair)?;

			ensure!(lp_token_burn > Zero::zero(), Error::<T>::ZeroLiquidity);

			let pool = Pools::<T>::get(&pool_id).ok_or(Error::<T>::PoolNotFound)?;

			let pool_account =
				T::PoolLocator::address(&pool_id).map_err(|_| Error::<T>::InvalidAssetPair)?;
			let (reserve1, reserve2) = Self::get_reserves(asset1.clone(), asset2.clone())?;

			let total_supply = T::PoolAssets::total_issuance(pool.lp_token.clone());
			let withdrawal_fee_amount = T::LiquidityWithdrawalFee::get() * lp_token_burn;
			let lp_redeem_amount = lp_token_burn.saturating_sub(withdrawal_fee_amount);

			let amount1 = Self::mul_div(&lp_redeem_amount, &reserve1, &total_supply)?;
			let amount2 = Self::mul_div(&lp_redeem_amount, &reserve2, &total_supply)?;

			ensure!(
				!amount1.is_zero() && amount1 >= amount1_min_receive,
				Error::<T>::AssetOneWithdrawalDidNotMeetMinimum
			);
			ensure!(
				!amount2.is_zero() && amount2 >= amount2_min_receive,
				Error::<T>::AssetTwoWithdrawalDidNotMeetMinimum
			);
			let reserve1_left = reserve1.saturating_sub(amount1);
			let reserve2_left = reserve2.saturating_sub(amount2);
			ensure!(
				reserve1_left >= T::Assets::minimum_balance(asset1.clone()),
				Error::<T>::ReserveLeftLessThanMinimal
			);
			ensure!(
				reserve2_left >= T::Assets::minimum_balance(asset2.clone()),
				Error::<T>::ReserveLeftLessThanMinimal
			);

			// burn the provided lp token amount that includes the fee
			T::PoolAssets::burn_from(
				pool.lp_token.clone(),
				who,
				lp_token_burn,
				Expendable,
				Exact,
				Polite,
			)?;

			T::Assets::transfer(asset1, &pool_account, withdraw_to, amount1, Expendable)?;
			T::Assets::transfer(asset2, &pool_account, withdraw_to, amount2, Expendable)?;
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

**File:** substrate/frame/asset-conversion/src/tests.rs (L422-466)
```rust
#[test]
fn add_tiny_liquidity_leads_to_insufficient_liquidity_minted_error() {
	new_test_ext().execute_with(|| {
		let user = 1;
		let token_1 = NativeOrWithId::Native;
		let token_2 = NativeOrWithId::WithId(2);

		create_tokens(user, vec![token_2.clone()]);
		assert_ok!(AssetConversion::create_pool(
			RuntimeOrigin::signed(user),
			Box::new(token_1.clone()),
			Box::new(token_2.clone())
		));

		assert_ok!(Balances::force_set_balance(RuntimeOrigin::root(), user, 1000));
		assert_ok!(Assets::mint(RuntimeOrigin::signed(user), 2, user, 1000));

		assert_noop!(
			AssetConversion::add_liquidity(
				RuntimeOrigin::signed(user),
				Box::new(token_1.clone()),
				Box::new(token_2.clone()),
				1,
				1,
				1,
				1,
				user
			),
			Error::<Test>::AmountOneLessThanMinimal
		);

		assert_noop!(
			AssetConversion::add_liquidity(
				RuntimeOrigin::signed(user),
				Box::new(token_1.clone()),
				Box::new(token_2.clone()),
				get_native_ed(),
				1,
				1,
				1,
				user
			),
			Error::<Test>::InsufficientLiquidityMinted
		);
	});
```
