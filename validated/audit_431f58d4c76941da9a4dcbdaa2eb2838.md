No vulnerability found for this question.

`pallet_asset_conversion::Pallet::get_reserves` does not have an analog to the Uniswap V2 ordering bug. Unlike `IUniswapV2Pair::getReserves()`, which returns an index-based `(reserve0, reserve1)` tuple that callers must correctly map to `token0`/`token1` by comparing addresses, this pallet's `get_reserves` looks up each balance explicitly by asset identity rather than by array position: `let balance1 = Self::get_balance(&pool_account, asset1); let balance2 = Self::get_balance(&pool_account, asset2);` [1](#0-0) . The doc comment explicitly states "The tuple result is in the order requested (not necessarily the same as pool order)", confirming the function is keyed by the caller-supplied `asset1`/`asset2` identity, not by an internal storage index that could be silently mismatched [2](#0-1) .

Every downstream consumer (`quote_price_exact_tokens_for_tokens`, `quote_price_tokens_for_exact_tokens`, `balance_path_from_amount_out`, `do_remove_liquidity`) calls `get_reserves(asset1, asset2)` with the same explicit asset pair used for the fee/quote lookup, so `balance1`/`balance2` are always semantically aligned to the requested assets, not to an arbitrary "reserve0/reserve1" storage slot [3](#0-2) [4](#0-3) [5](#0-4) . The same identity-based lookup is used in the EVM precompile wrapper, which decodes `asset1`/`asset2` and passes them straight through to `pallet_asset_conversion::Pallet::get_reserves` [6](#0-5) .

Because there is no `token0 == smaller_address` convention or positional `(reserve0, reserve1)` array being reused across mismatched contexts, the root cause described in the report — retrieving reserves in an unvalidated positional order — has no reachable analog in this FRAME pallet.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L913-920)
```rust
			let (reserve1, reserve2) = Self::get_reserves(asset1.clone(), asset2.clone())?;

			let total_supply = T::PoolAssets::total_issuance(pool.lp_token.clone());
			let withdrawal_fee_amount = T::LiquidityWithdrawalFee::get() * lp_token_burn;
			let lp_redeem_amount = lp_token_burn.saturating_sub(withdrawal_fee_amount);

			let amount1 = Self::mul_div(&lp_redeem_amount, &reserve1, &total_supply)?;
			let amount2 = Self::mul_div(&lp_redeem_amount, &reserve2, &total_supply)?;
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1309-1311)
```rust
				let (reserve_in, reserve_out) = Self::get_reserves(asset1.clone(), asset2.clone())?;
				balance_path.push((asset2, amount_in));
				amount_in = Self::get_amount_in(fee, &amount_in, &reserve_in, &reserve_out)?;
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1497-1514)
```rust
		/// Returns the balance of each asset in the pool.
		/// The tuple result is in the order requested (not necessarily the same as pool order).
		pub fn get_reserves(
			asset1: T::AssetKind,
			asset2: T::AssetKind,
		) -> Result<(T::Balance, T::Balance), Error<T>> {
			let pool_account = T::PoolLocator::pool_address(&asset1, &asset2)
				.map_err(|_| Error::<T>::InvalidAssetPair)?;

			let balance1 = Self::get_balance(&pool_account, asset1);
			let balance2 = Self::get_balance(&pool_account, asset2);

			if balance1.is_zero() || balance2.is_zero() {
				Err(Error::<T>::PoolEmpty)?;
			}

			Ok((balance1, balance2))
		}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1523-1547)
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
```

**File:** substrate/frame/asset-conversion/precompiles/src/lib.rs (L500-505)
```rust
		let asset1 = Self::decode_asset_kind(&call.asset1)?;
		let asset2 = Self::decode_asset_kind(&call.asset2)?;

		let (reserve1, reserve2) = pallet_asset_conversion::Pallet::<Runtime>::get_reserves(
			asset1, asset2,
		)
```
