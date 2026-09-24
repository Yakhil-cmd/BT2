### Title
Missing slippage protection (`amount_out_min: None`) in `SwapFirstAssetTrader::refund_weight` enables sandwich attacks on XCM fee refunds - ([File: cumulus/primitives/utility/src/lib.rs])

### Summary
`cumulus_primitives_utility::SwapFirstAssetTrader`, a `WeightTrader` implementation wired into production XCM configurations, performs two swaps against `pallet_asset_conversion` pools: `buy_weight` (protected, uses an exact target amount) and `refund_weight` (unprotected, passes `None` for `amount_out_min`). This asymmetry mirrors the exact bug class in the external report: a swap executed with a minimum-output of zero, exposing the transaction to MEV sandwich attacks.

### Finding Description
`SwapFirstAssetTrader::buy_weight` swaps the client-supplied fee asset into the `Target` asset via `SwapCredit::swap_tokens_for_exact_tokens`, requesting an exact `fee` amount, so it is inherently bounded [1](#0-0) .

However, `refund_weight` — invoked by the XCM executor to return unused weight fees at the end of message execution — swaps the `Target` asset back into the original payment asset using `SwapCredit::swap_exact_tokens_for_tokens` with an explicit `None` for `amount_out_min`: [2](#0-1) 

This contrasts with every other production caller of the same `SwapCredit`/pallet-asset-conversion swap primitives, which always supply an explicit minimum:
- `pallet_asset_conversion` extrinsics require a caller-supplied `amount_out_min`/`amount_in_max`, enforced by `ensure!(amount_out >= amount_out_min, Error::<T>::ProvidedMinimumNotSufficientForSwap)` [3](#0-2) .
- `SwapAssetAdapter::correct_and_deposit_fee` (transaction-payment-in-assets) quotes a price first and passes `Some(refund_asset_amount)` [4](#0-3) .
- `SingleAssetExchangeAdapter::exchange_asset` always passes `Some(want_amount)` for the maximal (exact-in) swap case [5](#0-4) .

`SwapFirstAssetTrader::refund_weight` is the only production code path that deliberately opts out of this protection.

`SwapFirstAssetTrader` is not test/mock-only: it is configured as the `Trader` in the Penpal parachain XCM configuration, alongside `UsingComponents`: [6](#0-5) 

### Impact Explanation
Whenever a user pays XCM execution fees with a non-native asset (via `BuyExecution`) and the actual weight consumed is less than the weight bought, `refund_weight` swaps the surplus `Target` asset back to the user's asset with zero minimum-output protection. Because `pallet_asset_conversion` pools are constant-product AMMs, an attacker can manipulate the pool's spot price immediately before this refund executes (e.g., by submitting a large swap in the same pool ahead of the block/message processing that triggers the refund, and reversing it afterward), causing the refund swap to execute at an unfavorable price. The value difference is captured by the attacker as arbitrage profit, at the expense of the account that should have received the refunded fee.

### Likelihood Explanation
This requires no privileged role: any account can pay XCM fees in a non-native asset that has a pool with `Target`, and any account can submit ordinary swap extrinsics against the same pool to manipulate price around the refund. It is a standard, permissionless sandwich pattern, identical in class to the referenced report, but the amount at risk is bounded by the (typically small) refunded weight-fee delta rather than an entire trade, and the pool must have enough depth/thinness to make the attack profitable net of the attacker's own round-trip AMM slippage/fees.

### Recommendation
`refund_weight` should compute an acceptable minimum output (e.g., via `QuotePrice::quote_price_exact_tokens_for_tokens` at the time of refund, with a configurable tolerance) and pass `Some(min_out)` to `SwapCredit::swap_exact_tokens_for_tokens` instead of `None`, consistent with how `buy_weight` and the other `SwapCredit`/`pallet_asset_conversion` callers already protect against unfavorable execution prices. If the quoted minimum cannot be met, the trader should either skip the refund-swap (keeping the surplus in `Target`) or apply a bounded/conservative default slippage tolerance rather than accept any price.

### Proof of Concept
No local Rust/FRAME reproduction was executed. Evidence assembled is limited to static code analysis:
- Confirmed guard difference between `buy_weight` (exact amount, implicitly bounded) and `refund_weight` (`None` minimum) at [1](#0-0)  vs [2](#0-1) .
- Confirmed production wiring of `SwapFirstAssetTrader` as an active `Trader` in `cumulus/parachains/runtimes/testing/penpal/src/xcm_config.rs`, and referenced (via grep) in `asset-hub-rococo`/`asset-hub-westend`/`staking-async` xcm configs and tests, indicating broader potential use, though I did not verify whether it is enabled in the live Rococo/Westend/Kusama/Polkadot Asset Hub runtimes versus only in test configs — this needs confirmation with a Devin session that can grep the full `xcm_config.rs` for those runtimes and check if `SwapFirstAssetTrader` is actually part of the `Trader` tuple there (my search only confirmed usage in Penpal's config directly; the Asset Hub references were only in `tests.rs`, not `xcm_config.rs`).
- No integration test was run to demonstrate an actual sandwich profit; this would require setting up a pool, executing `buy_weight`/`refund_weight` sequence, and interleaving an attacker swap, which was not performed here.

Given the incomplete confirmation of live-network reachability (Asset Hub vs. only test/Penpal), and that the impact is bounded to refund-fee deltas rather than full trade values, this should be treated as a **Low/Medium** severity finding pending confirmation of exact runtime deployment, similar in class and risk-acceptance posture to the original report.

### Citations

**File:** cumulus/primitives/utility/src/lib.rs (L469-475)
```rust
		let fee = WeightToFee::weight_to_fee(&weight);
		// swap the user's asset for the `Target` asset.
		let (credit_out, credit_change) = match SwapCredit::swap_tokens_for_exact_tokens(
			vec![swap_asset, Target::get()],
			credit_in,
			fee,
		) {
```

**File:** cumulus/primitives/utility/src/lib.rs (L539-545)
```rust
		let refund = self.total_fee.extract(refund_amount);
		let refund = match SwapCredit::swap_exact_tokens_for_tokens(
			vec![Target::get(), refund_swap_asset],
			refund,
			None,
		) {
			Ok(refund_in_target) => refund_in_target,
```

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

**File:** substrate/frame/transaction-payment/asset-conversion-tx-payment/src/payment.rs (L283-287)
```rust
		let (fee_asset_amount, adjusted_paid) = match S::swap_exact_tokens_for_tokens(
			vec![A::get(), asset_id],
			refund,
			Some(refund_asset_amount),
		) {
```

**File:** polkadot/xcm/xcm-builder/src/asset_exchange/single_asset_adapter/adapter.rs (L110-114)
```rust
			let credit_out = match <AssetConversion as SwapCredit<_>>::swap_exact_tokens_for_tokens(
				vec![swap_asset, want_asset_id],
				credit_in,
				Some(want_amount),
			) {
```

**File:** cumulus/parachains/runtimes/testing/penpal/src/xcm_config.rs (L408-422)
```rust
	type Trader = (
		// Allow native asset to pay the execution fee
		UsingComponents<WeightToFee, PenpalNativeCurrency, AccountId, Balances, ToAuthor<Runtime>>,
		// This trader allows to pay with any assets exchangeable to native asset with
		// [`AssetConversion`].
		cumulus_primitives_utility::SwapFirstAssetTrader<
			PenpalNativeCurrency,
			crate::AssetConversion,
			WeightToFee,
			crate::NativeAndAssets,
			(LocalAssetsConvertedConcreteId, ForeignAssetsConvertedConcreteId),
			ResolveAssetTo<StakingPot, crate::NativeAndAssets>,
			AccountId,
		>,
	);
```
