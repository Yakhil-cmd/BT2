No vulnerability found for this question.

Investigation summary: The reported issue is Solidity-specific (Olympus's `UniswapV2PoolTokenPrice.getPoolTokenPrice`), where scaling an LP token's total supply down to a smaller `outputDecimals_` value can floor to `0`, causing a division-by-zero revert in `mulDiv`. I looked for an analogous pattern in this Polkadot SDK fork's DEX/price logic: `pallet-asset-conversion`'s `quote`, `get_amount_out`, `get_amount_in`, `mul_div`, and `calc_lp_amount_for_zero_supply` in [1](#0-0) , plus `quote_price_exact_tokens_for_tokens` / `quote_price_tokens_for_exact_tokens` in [2](#0-1) .

Unlike the Solidity contract, every division here uses `checked_div`, which returns `None`/`Error` on a zero divisor rather than panicking or reverting unexpectedly, and callers explicitly guard against zero reserves/zero outputs (`get_reserves` errors on zero balances, quote functions return `None` for zero amounts and for outputs that round to zero) [3](#0-2) [4](#0-3) . This exact hardening is documented as an explicit fix in [5](#0-4) , and covered by regression tests such as `quote_price_returns_none_for_zero_output` [6](#0-5) .

There is no analog in this codebase to the Solidity bug's root cause — an oracle-style function that scales an LP token's total supply down to an externally-supplied "output decimals" value before using it as a division denominator. `pallet-asset-conversion` never scales pool/LP-token supply by an arbitrary output-decimals parameter; `pallet-psm`'s decimal-scaling helpers (`external_to_internal`/`internal_to_external`) also use `checked_div`/`checked_mul` with explicit zero-safe fallback (`unwrap_or_else(BalanceOf::<T>::zero)`) rather than an unguarded division [7](#0-6) . No unsigned-extrinsic-reachable or externally-triggerable division-by-zero revert of this bug class exists in the inspected production code.

### Citations

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

**File:** substrate/frame/asset-conversion/src/lib.rs (L1509-1513)
```rust
			if balance1.is_zero() || balance2.is_zero() {
				Err(Error::<T>::PoolEmpty)?;
			}

			Ok((balance1, balance2))
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1523-1562)
```rust
		pub fn quote_price_exact_tokens_for_tokens(
			asset1: T::AssetKind,
			asset2: T::AssetKind,
			amount: T::Balance,
			include_fee: bool,
		) -> Option<T::Balance> {
			// Swaps reject zero amounts, match that behavior.
			if amount.is_zero() {
				return None;
			}

			let pool_account = T::PoolLocator::pool_address(&asset1, &asset2).ok()?;

			let (balance1, balance2) = Self::get_reserves(asset1.clone(), asset2.clone()).ok()?;

			if balance1.is_zero() {
				return None;
			}

			let amount_out = if include_fee {
				let fee = Self::pool_fee_for(&asset1, &asset2).ok()?;
				Self::get_amount_out(fee, &amount, &balance1, &balance2).ok()?
			} else {
				Self::quote(&amount, &balance1, &balance2).ok()?
			};

			// Small inputs can round output to zero due to integer division.
			if amount_out.is_zero() {
				return None;
			}

			// Swap withdrawals from pools use `keep_alive=true` (Preserve). Use the same
			// preservation level to determine the actual withdrawable amount.
			let max_output = T::Assets::reducible_balance(asset2, &pool_account, Preserve, Polite);
			if amount_out > max_output {
				return None;
			}

			Some(amount_out)
		}
```

**File:** prdoc/stable2606/pr_11795.prdoc (L1-11)
```text
title: "Harden asset-conversion quote functions against zero amounts"
doc:
- audience: Runtime Dev
  description: |-
    Hardens `quote_price_exact_tokens_for_tokens` and `quote_price_tokens_for_exact_tokens` in
    `pallet-asset-conversion` to return `None` for zero input amounts and when integer rounding
    produces a zero output. Previously, zero inputs could propagate through the AMM math and
    zero outputs from small-input rounding were returned as `Some(0)`.
crates:
- name: pallet-asset-conversion
  bump: patch
```

**File:** substrate/frame/asset-conversion/src/tests.rs (L699-750)
```rust
#[test]
fn quote_price_returns_none_for_zero_output() {
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

		assert_ok!(Balances::force_set_balance(RuntimeOrigin::root(), user, 10_000_000));
		assert_ok!(Assets::mint(RuntimeOrigin::signed(user), 2, user, 1000));

		// Create a heavily skewed pool: lots of asset1, very little asset2.
		assert_ok!(AssetConversion::add_liquidity(
			RuntimeOrigin::signed(user),
			Box::new(token_1.clone()),
			Box::new(token_2.clone()),
			1_000_000,
			200,
			1,
			1,
			user,
		));

		// Tiny input into a skewed pool rounds output to zero.
		// get_amount_out(1, 1_000_000, 200) = 1*997*200 / (1_000_000*1000 + 997) = 0
		assert_eq!(
			AssetConversion::quote_price_exact_tokens_for_tokens(
				token_1.clone(),
				token_2.clone(),
				1,
				true,
			),
			None
		);
		// Without fees: quote(1, 1_000_000, 200) = 1*200/1_000_000 = 0
		assert_eq!(
			AssetConversion::quote_price_exact_tokens_for_tokens(
				token_1.clone(),
				token_2.clone(),
				1,
				false,
			),
			None
		);
	});
}
```

**File:** substrate/frame/psm/src/lib.rs (L1600-1619)
```rust
		pub(crate) fn external_to_internal(
			amount: BalanceOf<T>,
			ext_decimals: u8,
			internal_decimals: u8,
		) -> Result<BalanceOf<T>, Error<T>> {
			use core::cmp::Ordering::*;
			match ext_decimals.cmp(&internal_decimals) {
				Equal => Ok(amount),
				Less => {
					let diff = (internal_decimals - ext_decimals) as u32;
					let factor = Self::pow10(diff)?;
					amount.checked_mul(&factor).ok_or(Error::<T>::ConversionOverflow)
				},
				Greater => {
					let diff = (ext_decimals - internal_decimals) as u32;
					let factor = Self::pow10(diff)?;
					Ok(amount.checked_div(&factor).unwrap_or_else(BalanceOf::<T>::zero))
				},
			}
		}
```
