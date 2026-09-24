[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L813-844)
```rust
			let reserve1 = Self::get_balance(&pool_account, asset1.clone());
			let reserve2 = Self::get_balance(&pool_account, asset2.clone());

			let amount1: T::Balance;
			let amount2: T::Balance;
			if reserve1.is_zero() || reserve2.is_zero() {
				amount1 = amount1_desired;
				amount2 = amount2_desired;
			} else {
				let amount2_optimal = Self::quote(&amount1_desired, &reserve1, &reserve2)?;

				if amount2_optimal <= amount2_desired {
					ensure!(
						amount2_optimal >= amount2_min,
						Error::<T>::AssetTwoDepositDidNotMeetMinimum
					);
					amount1 = amount1_desired;
					amount2 = amount2_optimal;
				} else {
					let amount1_optimal = Self::quote(&amount2_desired, &reserve2, &reserve1)?;
					ensure!(
						amount1_optimal <= amount1_desired,
						Error::<T>::OptimalAmountLessThanDesired
					);
					ensure!(
						amount1_optimal >= amount1_min,
						Error::<T>::AssetOneDepositDidNotMeetMinimum
					);
					amount1 = amount1_optimal;
					amount2 = amount2_desired;
				}
			}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1370-1382)
```rust
		fn mul_div(a: &T::Balance, b: &T::Balance, c: &T::Balance) -> Result<T::Balance, Error<T>> {
			let a = T::HigherPrecisionBalance::from(*a);
			let b = T::HigherPrecisionBalance::from(*b);
			let c = T::HigherPrecisionBalance::from(*c);

			let result = a
				.checked_mul(&b)
				.ok_or(Error::<T>::Overflow)?
				.checked_div(&c)
				.ok_or(Error::<T>::Overflow)?;

			result.try_into().map_err(|_| Error::<T>::Overflow)
		}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3473-3522)
```rust
	/// Calculate the equivalent point of `new_funds` in a pool with `current_balance` and
	/// `current_points`.
	fn balance_to_point(
		current_balance: BalanceOf<T>,
		current_points: BalanceOf<T>,
		new_funds: BalanceOf<T>,
	) -> BalanceOf<T> {
		let u256 = T::BalanceToU256::convert;
		let balance = T::U256ToBalance::convert;
		match (current_balance.is_zero(), current_points.is_zero()) {
			(_, true) => new_funds.saturating_mul(POINTS_TO_BALANCE_INIT_RATIO.into()),
			(true, false) => {
				// The pool was totally slashed.
				// This is the equivalent of `(current_points / 1) * new_funds`.
				new_funds.saturating_mul(current_points)
			},
			(false, false) => {
				// Equivalent to (current_points / current_balance) * new_funds
				balance(
					u256(current_points)
						.saturating_mul(u256(new_funds))
						// We check for zero above
						.div(u256(current_balance)),
				)
			},
		}
	}

	/// Calculate the equivalent balance of `points` in a pool with `current_balance` and
	/// `current_points`.
	fn point_to_balance(
		current_balance: BalanceOf<T>,
		current_points: BalanceOf<T>,
		points: BalanceOf<T>,
	) -> BalanceOf<T> {
		let u256 = T::BalanceToU256::convert;
		let balance = T::U256ToBalance::convert;
		if current_balance.is_zero() || current_points.is_zero() || points.is_zero() {
			// There is nothing to unbond
			return Zero::zero();
		}

		// Equivalent of (current_balance / current_points) * points
		balance(
			u256(current_balance)
				.saturating_mul(u256(points))
				// We check for zero above
				.div(u256(current_points)),
		)
	}
```

**File:** substrate/frame/psm/src/lib.rs (L1541-1570)
```rust
		pub(crate) fn max_asset_debt(
			internal_asset: &T::AssetId,
			external_asset: &T::AssetId,
			info: &PsmInfo<T>,
		) -> BalanceOf<T> {
			let asset_weight = AssetCeilingWeight::<T>::get(internal_asset, external_asset);
			let total_weight = Self::total_ceiling_weight(internal_asset);
			Self::normalised_ceiling(asset_weight, total_weight, info.max_debt)
		}

		/// Sum of the configured ceiling weights across a PSM's approved externals.
		fn total_ceiling_weight(internal_asset: &T::AssetId) -> u32 {
			AssetCeilingWeight::<T>::iter_prefix(internal_asset)
				.map(|(_, w)| w.deconstruct())
				.fold(0u32, |acc, x| acc.saturating_add(x))
		}

		/// A single external's normalised debt ceiling: its share of the total weight applied
		/// to `max_debt`. Zero if the external (or the PSM as a whole) carries no weight.
		fn normalised_ceiling(
			asset_weight: Permill,
			total_weight: u32,
			max_debt: BalanceOf<T>,
		) -> BalanceOf<T> {
			let weight = asset_weight.deconstruct();
			if weight == 0 || total_weight == 0 {
				return BalanceOf::<T>::zero();
			}
			Perbill::from_rational(weight, total_weight).mul_floor(max_debt)
		}
```

**File:** substrate/frame/psm/src/tests.rs (L295-317)
```rust
	#[test]
	fn boundary_new_debt_equals_max() {
		new_test_ext().execute_with(|| {
			// Set USDC to 100% and USDT to 0% so USDC gets full ceiling
			set_max_debt(200_000 * INTERNAL_UNIT);
			set_asset_ceiling_weight(USDC_ASSET_ID, Permill::from_percent(100));
			set_asset_ceiling_weight(USDT_ASSET_ID, Permill::from_percent(0));

			let max_debt = psm_max_asset_debt(USDC_ASSET_ID);

			fund_external_asset(USDC_ASSET_ID, ALICE, max_debt);

			assert_ok!(Psm::mint(
				RuntimeOrigin::signed(ALICE),
				INTERNAL_ASSET_ID,
				USDC_ASSET_ID,
				max_debt,
				Permill::from_percent(1)
			));

			assert_eq!(PsmDebt::<Test>::get(INTERNAL_ASSET_ID, USDC_ASSET_ID), max_debt);
		});
	}
```
