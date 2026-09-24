No vulnerability found for this question.

Based on my research, the polkadot-sdk analog of a DEX swap function — `pallet_asset_conversion::Pallet::do_swap_exact_tokens_for_tokens` / `do_swap_tokens_for_exact_tokens` — always enforces explicit slippage protection before any state mutation, unlike the DODO `MarginTrading._opentrade` function that performs a raw `.call()` with no minimum-output check.

Specifically:
- The extrinsics `swap_exact_tokens_for_tokens` and `swap_tokens_for_exact_tokens` require callers to supply `amount_out_min` / `amount_in_max`, and the internal implementation enforces them with `ensure!(amount_out >= amount_out_min, Error::<T>::ProvidedMinimumNotSufficientForSwap)` and the analogous check for the max-input path before any transfer occurs. [1](#0-0) [2](#0-1) 
- The credit-based `SwapCredit` variants used by cross-pallet callers (XCM fee-swapping, tx-payment) enforce the same bounds. [3](#0-2) [4](#0-3) 
- The `revive` precompile wrapper for the pallet forwards the caller-supplied `amountOutMin` straight into the checked `Swap::swap_exact_tokens_for_tokens` call, and there is a dedicated test verifying that an excessive `amountOutMin` causes the call to fail. [5](#0-4) [6](#0-5) 
- The XCM `ExchangeAsset` instruction, handled through `SingleAssetExchangeAdapter::exchange_asset`, also always passes a `want_amount` bound into `swap_exact_tokens_for_tokens`/`swap_tokens_for_exact_tokens`, enforcing a minimum-out or maximum-in constraint depending on the `maximal` flag, and reverts the whole instruction (`XcmError::NoDeal`) if unmet. [7](#0-6) [8](#0-7) 
- There's an explicit regression test (`swap_should_not_work_if_too_much_slippage`) confirming the check is active. [9](#0-8) 

There is no code path found where a user-facing swap operation (extrinsic, precompile, or XCM `ExchangeAsset`) executes a token exchange without a caller-supplied and enforced minimum-output/maximum-input bound. The DODO report's root cause — an unchecked raw external call performing a swap with no slippage parameter at all — has no structural analog in this codebase's swap-related entry points.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L987-1002)
```rust
		) -> Result<T::Balance, DispatchError> {
			ensure!(amount_in > Zero::zero(), Error::<T>::ZeroAmount);
			if let Some(amount_out_min) = amount_out_min {
				ensure!(amount_out_min > Zero::zero(), Error::<T>::ZeroAmount);
			}

			Self::validate_swap_path(&path)?;
			let path = Self::balance_path_from_amount_in(amount_in, path)?;

			let amount_out = path.last().map(|(_, a)| *a).ok_or(Error::<T>::InvalidPath)?;
			if let Some(amount_out_min) = amount_out_min {
				ensure!(
					amount_out >= amount_out_min,
					Error::<T>::ProvidedMinimumNotSufficientForSwap
				);
			}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1036-1050)
```rust
			ensure!(amount_out > Zero::zero(), Error::<T>::ZeroAmount);
			if let Some(amount_in_max) = amount_in_max {
				ensure!(amount_in_max > Zero::zero(), Error::<T>::ZeroAmount);
			}

			Self::validate_swap_path(&path)?;
			let path = Self::balance_path_from_amount_out(amount_out, path)?;

			let amount_in = path.first().map(|(_, a)| *a).ok_or(Error::<T>::InvalidPath)?;
			if let Some(amount_in_max) = amount_in_max {
				ensure!(
					amount_in <= amount_in_max,
					Error::<T>::ProvidedMaximumNotSufficientForSwap
				);
			}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1080-1097)
```rust
			let amount_in = credit_in.peek();
			let inspect_path = |credit_asset| {
				ensure!(
					path.first().map_or(false, |a| *a == credit_asset),
					Error::<T>::InvalidPath
				);
				ensure!(!amount_in.is_zero(), Error::<T>::ZeroAmount);
				ensure!(amount_out_min.map_or(true, |a| !a.is_zero()), Error::<T>::ZeroAmount);

				Self::validate_swap_path(&path)?;
				let path = Self::balance_path_from_amount_in(amount_in, path)?;

				let amount_out = path.last().map(|(_, a)| *a).ok_or(Error::<T>::InvalidPath)?;
				ensure!(
					amount_out_min.map_or(true, |a| amount_out >= a),
					Error::<T>::ProvidedMinimumNotSufficientForSwap
				);
				Ok((path, amount_out))
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1129-1144)
```rust
			let inspect_path = |credit_asset| {
				ensure!(
					path.first().map_or(false, |a| a == &credit_asset),
					Error::<T>::InvalidPath
				);
				ensure!(amount_in_max > Zero::zero(), Error::<T>::ZeroAmount);
				ensure!(amount_out > Zero::zero(), Error::<T>::ZeroAmount);

				Self::validate_swap_path(&path)?;
				let path = Self::balance_path_from_amount_out(amount_out, path)?;

				let amount_in = path.first().map(|(_, a)| *a).ok_or(Error::<T>::InvalidPath)?;
				ensure!(
					amount_in <= amount_in_max,
					Error::<T>::ProvidedMaximumNotSufficientForSwap
				);
```

**File:** substrate/frame/asset-conversion/precompiles/src/lib.rs (L305-314)
```rust
		let amount_out = <pallet_asset_conversion::Pallet<Runtime> as Swap<
			<Runtime as frame_system::Config>::AccountId,
		>>::swap_exact_tokens_for_tokens(
			sender,
			path,
			Self::to_balance(call.amountIn)?,
			Some(Self::to_balance(call.amountOutMin)?),
			send_to,
			call.keepAlive,
		)?;
```

**File:** substrate/frame/asset-conversion/precompiles/src/tests.rs (L298-319)
```rust
#[test]
fn swap_fails_with_insufficient_output() {
	new_test_ext().execute_with(|| {
		let provider = 1u64;
		let swapper = 2u64;

		setup_pool(provider, 10_000, 10_000);
		assert_ok!(Assets::mint(RuntimeOrigin::signed(provider), 1, swapper, 1_000));

		let data = IAssetConversion::swapExactTokensForTokensCall {
			path: vec![encode_asset(1).into(), encode_native().into()],
			amountIn: U256::from(100),
			amountOutMin: U256::from(999_999),
			sendTo: account_addr(&swapper),
			keepAlive: false,
		}
		.abi_encode();

		let result = bare_call(swapper, data);
		assert!(did_fail(&result), "swap with excessive amountOutMin must fail");
	});
}
```

**File:** polkadot/xcm/xcm-builder/src/asset_exchange/single_asset_adapter/adapter.rs (L106-159)
```rust
		// Do the swap.
		let (credit_out, maybe_credit_change) = if maximal {
			// If `maximal`, then we swap exactly `credit_in` to get as much of `want_asset_id` as
			// we can, with a minimum of `want_amount`.
			let credit_out = match <AssetConversion as SwapCredit<_>>::swap_exact_tokens_for_tokens(
				vec![swap_asset, want_asset_id],
				credit_in,
				Some(want_amount),
			) {
				Ok(inner) => inner,
				Err((credit_in, error)) => {
					tracing::debug!(
						target: "xcm::SingleAssetExchangeAdapter::exchange_asset",
						?error,
						"Could not perform the swap"
					);
					// put back the taken credit
					let taken = AssetsInHolding::new_from_fungible_credit(
						give_asset.id.clone(),
						Box::new(credit_in),
					);
					give.subsume_assets(taken);
					return Err(give);
				},
			};
			// We don't have leftover assets if exchange was maximal.
			(credit_out, None)
		} else {
			// If `minimal`, then we swap as little of `credit_in` as we can to get exactly
			// `want_amount` of `want_asset_id`.
			let (credit_out, credit_change) =
				match <AssetConversion as SwapCredit<_>>::swap_tokens_for_exact_tokens(
					vec![swap_asset, want_asset_id],
					credit_in,
					want_amount,
				) {
					Ok(inner) => inner,
					Err((credit_in, error)) => {
						tracing::debug!(
							target: "xcm::SingleAssetExchangeAdapter::exchange_asset",
							?error,
							"Could not perform the swap",
						);
						// put back the taken credit
						let taken = AssetsInHolding::new_from_fungible_credit(
							give_asset.id.clone(),
							Box::new(credit_in),
						);
						give.subsume_assets(taken);
						return Err(give);
					},
				};
			(credit_out, if credit_change.peek() > 0 { Some(credit_change) } else { None })
		};
```

**File:** polkadot/xcm/xcm-executor/src/lib.rs (L1755-1771)
```rust
			ExchangeAsset { give, want, maximal } => {
				self.transactional_process(|self_ref| {
					let give = self_ref.holding.saturating_take(give);
					self_ref.ensure_can_subsume_assets(want.len())?;
					let received = Config::AssetExchanger::exchange_asset(
						self_ref.origin_ref(),
						give,
						&want,
						maximal,
					).map_err(|unspent| {
						self_ref.holding.subsume_assets(unspent);
						XcmError::NoDeal
					})?;
					self_ref.holding.subsume_assets(received);
					Ok(())
				})
			},
```

**File:** substrate/frame/asset-conversion/src/tests.rs (L1565-1614)
```rust
#[test]
fn swap_should_not_work_if_too_much_slippage() {
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

		assert_ok!(Balances::force_set_balance(
			RuntimeOrigin::root(),
			user,
			10000 + get_native_ed()
		));
		assert_ok!(Assets::mint(RuntimeOrigin::signed(user), 2, user, 1000));

		let liquidity1 = 10000;
		let liquidity2 = 200;

		assert_ok!(AssetConversion::add_liquidity(
			RuntimeOrigin::signed(user),
			Box::new(token_1.clone()),
			Box::new(token_2.clone()),
			liquidity1,
			liquidity2,
			1,
			1,
			user,
		));

		let exchange_amount = 100;

		assert_noop!(
			AssetConversion::swap_exact_tokens_for_tokens(
				RuntimeOrigin::signed(user),
				bvec![token_2.clone(), token_1.clone()],
				exchange_amount, // amount_in
				4000,            // amount_out_min
				user,
				false,
			),
			Error::<Test>::ProvidedMinimumNotSufficientForSwap
		);
	});
}
```
