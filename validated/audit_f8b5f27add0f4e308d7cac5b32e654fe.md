No vulnerability found for this question.

The reported issue is a classic bonding-curve slippage/front-running problem, which is explicitly excluded by the assessment rules ("pure front-running/economic attacks"). I also checked the closest architectural analog in the Polkadot SDK — the AMM/bonding-curve style pallet `pallet-asset-conversion` — and found that it already implements the exact mitigation the report recommends: both `swap_exact_tokens_for_tokens` and `swap_tokens_for_exact_tokens` (and their `SwapCredit` counterparts used for credit-based swaps) require an `amount_out_min` / `amount_in_max` parameter that is checked against the actual computed amount before the swap executes, failing with `Error::<T>::ProvidedMinimumNotSufficientForSwap` / `ProvidedMaximumNotSufficientForSwap` otherwise [1](#0-0) . This pattern is exercised by dedicated slippage tests such as `swap_should_not_work_if_too_much_slippage` and `swap_tokens_for_exact_tokens_should_not_work_if_too_much_slippage` [2](#0-1) [3](#0-2) , and the credit-based path (`SwapCredit`) enforces the same bound at `do_swap_exact_credit_tokens_for_tokens` [4](#0-3) . The public precompile interface exposed to contracts also forwards `amountOutMin`/`amountInMax` faithfully into the pallet call [5](#0-4) , and this is proven by the `swap_fails_with_insufficient_output` test [6](#0-5) .

Since the missing-check pattern from the report does not exist in the analogous Substrate/FRAME AMM-style code path, and the underlying bug class (slippage/front-running via mempool ordering) is out of scope per the assessment rules, there is no demonstrable analog vulnerability to report.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L989-1002)
```rust
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

**File:** substrate/frame/asset-conversion/src/lib.rs (L1075-1109)
```rust
		pub(crate) fn do_swap_exact_credit_tokens_for_tokens(
			path: Vec<T::AssetKind>,
			credit_in: CreditOf<T>,
			amount_out_min: Option<T::Balance>,
		) -> Result<CreditOf<T>, (CreditOf<T>, DispatchError)> {
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
			};
			let (path, amount_out) = match inspect_path(credit_in.asset()) {
				Ok((p, a)) => (p, a),
				Err(e) => return Err((credit_in, e)),
			};

			let credit_out = Self::credit_swap(credit_in, &path)?;

			Self::deposit_event(Event::SwapCreditExecuted { amount_in, amount_out, path });

			Ok(credit_out)
		}
```

**File:** substrate/frame/asset-conversion/src/tests.rs (L1565-1613)
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
```

**File:** substrate/frame/asset-conversion/src/tests.rs (L2037-2084)
```rust
fn swap_tokens_for_exact_tokens_should_not_work_if_too_much_slippage() {
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
			20000 + get_native_ed()
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

		let exchange_out = 1;

		assert_noop!(
			AssetConversion::swap_tokens_for_exact_tokens(
				RuntimeOrigin::signed(user),
				bvec![token_1.clone(), token_2.clone()],
				exchange_out, // amount_out
				50,           // amount_in_max just greater than slippage.
				user,
				true
			),
			Error::<Test>::ProvidedMaximumNotSufficientForSwap
		);
	});
```

**File:** substrate/frame/asset-conversion/precompiles/src/lib.rs (L289-319)
```rust
	fn swap_exact_tokens_for_tokens(
		call: &IAssetConversion::swapExactTokensForTokensCall,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		let path_len = Self::validated_path_len(&call.path)?;
		env.charge(
			<Runtime as pallet_asset_conversion::Config>::WeightInfo::swap_exact_tokens_for_tokens(
				path_len,
			),
		)?;
		let path: Vec<_> =
			call.path.iter().map(|e| Self::decode_asset_kind(e)).collect::<Result<_, _>>()?;

		let sender = Self::caller_account_id(env)?;
		let send_to = env.to_account_id(&H160(call.sendTo.0 .0));

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

		Ok(IAssetConversion::swapExactTokensForTokensCall::abi_encode_returns(&Self::to_u256(
			amount_out,
		)?))
	}
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
