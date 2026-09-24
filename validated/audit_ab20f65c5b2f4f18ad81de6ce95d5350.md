## Analog Found: Missing slippage control in XCM fee-refund swap [1](#0-0) 

### Title
`SwapFirstAssetTrader::refund_weight` swaps overpaid XCM execution fees back to the origin asset with no minimum-output protection - ([File: cumulus/primitives/utility/src/lib.rs])

### Summary
`SwapFirstAssetTrader` is a `WeightTrader` implementation used by parachain XCM executors (asset-hub-westend, asset-hub-rococo, penpal, staking-async parachain) to let users pay XCM execution fees in a non-native fungible asset by swapping it into the runtime's target fee asset via `pallet_asset_conversion`'s `SwapCredit` trait. When the message consumes less weight than was charged for, `refund_weight` swaps the unused portion of the target asset back into the asset the user originally paid with — but it calls `SwapCredit::swap_exact_tokens_for_tokens` with `amount_out_min` hard-coded to `None`, i.e. zero slippage protection, exactly analogous to the AutoCompounder.sol pattern of passing `amountOutMin = 0`.

### Finding Description
`buy_weight` correctly uses the *exact-output* swap `swap_tokens_for_exact_tokens(vec![swap_asset, Target], credit_in, fee)`, so the fee amount is fixed and any surplus input is returned unswapped — no slippage risk there [2](#0-1) .

However, `refund_weight` performs the reverse conversion — turning the unused, already-swapped `Target` credit back into the original payment asset — using the *exact-input* swap with no floor:
```rust
let refund = match SwapCredit::swap_exact_tokens_for_tokens(
    vec![Target::get(), refund_swap_asset],
    refund,
    None,   // <-- amount_out_min hard-coded to None
) {
``` [1](#0-0) 

`pallet_asset_conversion`'s `do_swap_exact_credit_tokens_for_tokens` fully honors an `Option<amount_out_min>` and enforces `ProvidedMinimumNotSufficientForSwap` when a caller supplies one [3](#0-2) , so the pallet itself is not at fault — the missing protection is introduced entirely by this caller in `cumulus/primitives/utility`, which is the direct analog of the AutoCompounder.sol contract hard-coding `0` where a real minimum could have been computed from the amount already known before the swap (the pre-swap target-asset amount and the known reserves are available to `refund_weight` at call time).

`pallet_asset_conversion` pools are fully permissionless: any account can call `create_pool`, `add_liquidity`, `remove_liquidity`, or `swap_exact_tokens_for_tokens`/`swap_tokens_for_exact_tokens` to move reserves [4](#0-3) , so an attacker with an ordinary signed account (no privileged role) can shift a pool's price before an XCM message executes and shift it back afterward, or otherwise arrange execution ordering around the fee-refund swap, and the refund executed via `refund_weight` will accept whatever price results, with no on-chain floor to reject an adverse rate.

### Impact Explanation
If exploited, the refund the XCM sender receives back in their original payment asset can be worth substantially less than the fair-value amount, with the difference captured by whoever manipulates the pool's reserves around the swap (classic sandwich pattern). This is a value-extraction/MEV issue against XCM fee payers using `SwapFirstAssetTrader`-configured chains, matching the reported bug class (Medium: slippage-less swap exposed to sandwich/MEV) rather than a critical fund-theft or consensus-safety issue, because it only affects the *change* returned from an already-paid fee, bounded by the total fee paid for the message.

### Likelihood Explanation
Likelihood depends on (a) an attacker being able to influence block/message ordering relative to the victim XCM message on the specific parachain (collator-level MEV/ordering control, which is chain- and network-specific and was not verified here), and (b) the swap pool for the relevant asset pair having thin enough liquidity for a profitable sandwich net of swap fees. I was not able to verify from the indexed code whether the target parachains' block-building pipeline exposes this kind of ordering control to an unprivileged actor (this is an assumption inherent to the report's own MEV framing, and the report itself notes that on Optimism this required "a protocol change" to become exploitable — the Polkadot/Cumulus analog would similarly depend on collator/sequencer behavior, which is outside what the indexed source establishes).

### Recommendation
In `refund_weight`, compute a bound on the acceptable refund output before calling `swap_exact_tokens_for_tokens`, e.g. by quoting via `QuotePrice`/`quote_price_exact_tokens_for_tokens` (already used elsewhere in this trader family, see `quote_weight`) immediately before the swap and passing `Some(min_amount)` with a small, governance-configured tolerance, instead of `None`. Alternatively, skip the second swap when the refund amount is small enough that the price-impact/slippage risk exceeds its value, or restrict the swap path length/liquidity source to pools with a minimum-liquidity guard.

### Proof of Concept
No executable PoC was produced. This is an analog identified purely from static code inspection of `cumulus/primitives/utility/src/lib.rs` and `substrate/frame/asset-conversion/src/lib.rs`; I did not build a Rust/FRAME integration test reproducing an actual profitable sandwich against `SwapFirstAssetTrader::refund_weight` (which would require constructing a full XCM executor test harness with a `pallet_asset_conversion` pool, a `SwapFirstAssetTrader`-configured trader, and interleaved extrinsics/messages to manipulate reserves), nor did I confirm collator-level transaction/message ordering control on the affected runtimes (asset-hub-westend, asset-hub-rococo, penpal, staking-async parachain — confirmed only via `grep_search` usage sites, not read in full). This should be treated as a credible but unverified Medium-severity lead requiring further reachability/ordering analysis before submission.

### Citations

**File:** cumulus/primitives/utility/src/lib.rs (L469-489)
```rust
		let fee = WeightToFee::weight_to_fee(&weight);
		// swap the user's asset for the `Target` asset.
		let (credit_out, credit_change) = match SwapCredit::swap_tokens_for_exact_tokens(
			vec![swap_asset, Target::get()],
			credit_in,
			fee,
		) {
			Ok(a) => a,
			Err((credit_in, error)) => {
				log::trace!(
					target: "xcm::weight",
					"SwapFirstAssetTrader::buy_weight swap couldn't be done. Error was: {:?}",
					error,
				);
				// put back the taken credit
				let taken =
					AssetsInHolding::new_from_fungible_credit(id.clone(), Box::new(credit_in));
				payment.subsume_assets(taken);
				return Err((payment, XcmError::FeesNotMet));
			},
		};
```

**File:** cumulus/primitives/utility/src/lib.rs (L539-544)
```rust
		let refund = self.total_fee.extract(refund_amount);
		let refund = match SwapCredit::swap_exact_tokens_for_tokens(
			vec![Target::get(), refund_swap_asset],
			refund,
			None,
		) {
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L493-573)
```rust
		/// burned in the process. With the usage of `amount1_min_receive`/`amount2_min_receive`
		/// it's possible to control the min amount of returned tokens you're happy with.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::remove_liquidity())]
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

		/// Swap the exact amount of `asset1` into `asset2`.
		/// `amount_out_min` param allows you to specify the min amount of the `asset2`
		/// you're happy to receive.
		///
		/// [`AssetConversionApi::quote_price_exact_tokens_for_tokens`] runtime call can be called
		/// for a quote.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::swap_exact_tokens_for_tokens(path.len() as u32))]
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

		/// Swap any amount of `asset1` to get the exact amount of `asset2`.
		/// `amount_in_max` param allows to specify the max amount of the `asset1`
		/// you're happy to provide.
		///
		/// [`AssetConversionApi::quote_price_tokens_for_exact_tokens`] runtime call can be called
		/// for a quote.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::swap_tokens_for_exact_tokens(path.len() as u32))]
		pub fn swap_tokens_for_exact_tokens(
			origin: OriginFor<T>,
			path: Vec<Box<T::AssetKind>>,
			amount_out: T::Balance,
			amount_in_max: T::Balance,
			send_to: T::AccountId,
			keep_alive: bool,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::do_swap_tokens_for_exact_tokens(
				sender,
				path.into_iter().map(|a| *a).collect(),
				amount_out,
				Some(amount_in_max),
				send_to,
				keep_alive,
			)?;
			Ok(())
		}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1075-1096)
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
```
