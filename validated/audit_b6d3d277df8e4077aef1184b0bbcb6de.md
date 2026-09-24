No vulnerability found for this question.

The reported issue is specific to `UniV3SwapInput` hardcoding `amountOutMinimum: 0` and omitting the `deadline` field in a Solidity Uniswap V3 integration. The closest FRAME analog is `pallet_asset_conversion`'s swap entry points, but they do not share either defect:

- `swap_exact_tokens_for_tokens` in `substrate/frame/asset-conversion/src/lib.rs` requires the caller to supply `amount_out_min` as an explicit, non-optional extrinsic argument (not hardcoded to zero), and `do_swap_exact_tokens_for_tokens` enforces `amount_out >= amount_out_min` via `Error::<T>::ProvidedMinimumNotSufficientForSwap` before completing the swap. [1](#0-0) [2](#0-1) 
- The `Swap`/`SwapCredit` trait implementations (`swap.rs`) preserve this `amount_out_min`/`amount_in_max` slippage control end-to-end, including for the credit-based variants used cross-pallet. [3](#0-2) [4](#0-3) 
- The `pallet-revive` precompile wrapper (`IAssetConversion.swapExactTokensForTokens`) also forwards the caller-supplied `amountOutMin` straight into the pallet call rather than hardcoding it. [5](#0-4) 
- Existing tests (`swap_should_not_work_if_too_much_slippage`, `swap_tokens_for_exact_tokens_should_not_work_if_too_much_slippage`) confirm the minimum/maximum checks are actively enforced, not bypassable. [6](#0-5) [7](#0-6) 

Additionally, "deadline" in the EVM sense (a transaction-level expiry parameter checked inside business logic) has no direct analog need in FRAME: extrinsic mortality/expiry is handled independently by the transaction's era/mortality checking extension, not by the swap function itself, so there is no equivalent "commented-out deadline" pattern to exploit here.

Since both the missing-deadline and hardcoded-zero-slippage root causes from the report are absent in this codebase's swap logic, no supported analog vulnerability exists.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L527-545)
```rust
		pub fn swap_exact_tokens_for_tokens(
			origin: OriginFor<T>,
			path: Vec<Box<T::AssetKind>>,
			amount_in: T::Balance,
			amount_out_min: T::Balance,
			send_to: T::AccountId,
			keep_alive: bool,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::do_swap_exact_tokens_for_tokens(
				sender,
				path.into_iter().map(|a| *a).collect(),
				amount_in,
				Some(amount_out_min),
				send_to,
				keep_alive,
			)?;
			Ok(())
		}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L988-1002)
```rust
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

**File:** substrate/frame/asset-conversion/src/swap.rs (L33-50)
```rust
	/// Swap exactly `amount_in` of asset `path[0]` for asset `path[last]`.
	/// If an `amount_out_min` is specified, it will return an error if it is unable to acquire
	/// the amount desired.
	///
	/// Withdraws the `path[0]` asset from `sender`, deposits the `path[last]` asset to `send_to`,
	/// respecting `keep_alive`.
	///
	/// If successful, returns the amount of `path[last]` acquired for the `amount_in`.
	///
	/// This operation is expected to be atomic.
	fn swap_exact_tokens_for_tokens(
		sender: AccountId,
		path: Vec<Self::AssetKind>,
		amount_in: Self::Balance,
		amount_out_min: Option<Self::Balance>,
		send_to: AccountId,
		keep_alive: bool,
	) -> Result<Self::Balance, DispatchError>;
```

**File:** substrate/frame/asset-conversion/src/swap.rs (L155-172)
```rust
	#[transactional]
	fn swap_exact_tokens_for_tokens(
		sender: T::AccountId,
		path: Vec<Self::AssetKind>,
		amount_in: Self::Balance,
		amount_out_min: Option<Self::Balance>,
		send_to: T::AccountId,
		keep_alive: bool,
	) -> Result<Self::Balance, DispatchError> {
		Self::do_swap_exact_tokens_for_tokens(
			sender,
			path,
			amount_in,
			amount_out_min,
			send_to,
			keep_alive,
		)
	}
```

**File:** substrate/frame/asset-conversion/precompiles/src/lib.rs (L289-314)
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

**File:** substrate/frame/asset-conversion/src/tests.rs (L2036-2083)
```rust
#[test]
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
```
