`SwapFirstAssetTrader` is wired up as an XCM `WeightTrader` in production runtime configs (`cumulus/parachains/runtimes/assets/asset-hub-rococo/src/xcm_config.rs`, `asset-hub-westend/src/xcm_config.rs`, `penpal/src/xcm_config.rs`, `substrate/frame/staking-async/runtimes/parachain/src/xcm_config.rs`), confirming it is reachable production code, not test-only.

### Title
Missing slippage protection in `SwapFirstAssetTrader::refund_weight` XCM fee-refund swap - ([File: cumulus/primitives/utility/src/lib.rs])

### Summary
`SwapFirstAssetTrader::refund_weight` swaps back unspent XCM execution fees from the `Target` fee asset into the client's original payment asset by calling `SwapCredit::swap_exact_tokens_for_tokens` with `amount_out_min` hardcoded to `None`, i.e. no minimum output is enforced for the refund swap.

### Finding Description
`SwapFirstAssetTrader` is a `WeightTrader` used to let users pay XCM execution fees in a non-native asset by swapping it (via `pallet_asset_conversion`'s `SwapCredit`) into the runtime's target fee asset. In `buy_weight`, the swap into the target asset correctly uses `swap_tokens_for_exact_tokens` (an exact-output swap that bounds the input amount, so this side is protected by construction).

However, in `refund_weight` the reverse conversion — converting unused `Target` fee credit back to the user's original asset — calls: [1](#0-0) 

with `None` passed as `amount_out_min`. Per `pallet_asset_conversion::SwapCredit::swap_exact_tokens_for_tokens`, when `amount_out_min` is `None`, no floor is enforced on the acquired output and the swap will execute purely at the current pool exchange rate: [2](#0-1) 

This is the same class of defect as the reported Tokemak issue: a swap invoked with an unbounded/zero minimum-output parameter, exposing the caller to price movement (e.g., another party manipulating the `Target`/refund-asset pool reserves within the same block or via preceding transactions) between quoting and execution. Unlike `buy_weight`, which is bounded because it uses an exact-output swap, `refund_weight`'s exact-input swap has no output floor at all, so an adverse pool state at execution time can silently reduce the refund the user receives, with the shortfall staying with the runtime/pool rather than the user.

### Impact Explanation
The impact is a value loss to the user submitting an XCM message that pays fees through `SwapFirstAssetTrader` in an asset other than `Target`: the returned unused-weight refund can be arbitrarily smaller than the fair-market-rate refund if the swap-back pool's price is unfavorable at execution time (e.g. due to a preceding trade against the same pool within the block, or normal price drift for pools with thin liquidity). This is confined to the refund amount (a fraction of total fees for unused weight), not principal funds, and requires a real asset-conversion pool to exist for the `Target -> client asset` pair configured in a runtime using this trader.

### Likelihood Explanation
Likelihood is Medium: it requires (a) a production runtime configuring `SwapFirstAssetTrader` as (part of) its `WeightTrader` (present in AssetHub Rococo/Westend and Penpal test configs) and (b) a low-liquidity or otherwise moveable `Target`↔`asset` pool, plus an actor able to shift the pool price before the refund executes (e.g. via a preceding, non-privileged swap in the same or an earlier block/extrinsic). No privileged role or governance access is needed — any ordinary user submitting an XCM message that triggers `buy_weight`/`refund_weight` on a pool they (or anyone) can also trade against is sufficient to demonstrate value leakage; whether this is currently instantiated in any *live* Parity bounty-eligible chain's actual runtime configuration was not confirmed within the scope of this investigation.

### Recommendation
Pass a real minimum-output bound to the refund swap rather than `None`, e.g. compute an acceptable minimum via `QuotePrice::quote_price_exact_tokens_for_tokens` (already used elsewhere in this file) before calling `swap_exact_tokens_for_tokens`, and treat a failed/insufficient swap the same way `Err` is already handled (returning credit to `total_fee` and skipping the refund) rather than accepting an unbounded-worse outcome.

### Proof of Concept
No dynamic execution was performed; this is a static-analysis finding based on direct code inspection. Evidence of the flawed guard:
- Refund swap call site with `None` minimum: [3](#0-2) 
- Contrast with the properly-bounded forward swap in `buy_weight`, which uses `swap_tokens_for_exact_tokens` with an exact `fee` target: [4](#0-3) 
- Confirmation that `amount_out_min: None` disables the check in `pallet_asset_conversion`: [2](#0-1) 
- Existing unit tests (`cumulus/primitives/utility/src/tests/swap_first.rs`) exercise `refund_weight` only with a 1:1 mock swap and never assert behavior when the underlying pool price is adverse, so the missing-slippage-bound scenario is not covered by current test harnesses: [5](#0-4) 

No test was executed against a live network or with real adversarial pool manipulation; a full reproduction would require constructing an integration test with a `SwapCredit` backed by `pallet_asset_conversion` where a third party moves the `Target`/refund-asset pool price between `buy_weight` and `refund_weight` calls in the same XCM execution, and asserting the refunded amount is below the fair-quote amount despite `refund_weight` returning `Ok`/`Some`. This was not run in this session.

### Citations

**File:** cumulus/primitives/utility/src/lib.rs (L471-475)
```rust
		let (credit_out, credit_change) = match SwapCredit::swap_tokens_for_exact_tokens(
			vec![swap_asset, Target::get()],
			credit_in,
			fee,
		) {
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

**File:** cumulus/primitives/utility/src/tests/swap_first.rs (L132-170)
```rust
#[test]
fn buy_and_refund_twice_for_target() {
	let client_asset_total = 15;
	let fee = 5;
	let refund1 = 4;
	let refund2 = 2;

	setup_pool(CLIENT_ASSET, 1000, TARGET_ASSET, 1000);
	// create pool for refund swap.
	setup_pool(TARGET_ASSET, 1000, CLIENT_ASSET, 1000);

	let holding_asset = create_holding_asset(CLIENT_ASSET, client_asset_total);
	let holding_change = create_holding_asset(CLIENT_ASSET, client_asset_total - fee);
	let refund_asset = create_holding_asset(CLIENT_ASSET, refund1);

	let target_total = Fungibles::total_issuance(TARGET_ASSET);
	let client_total = Fungibles::total_issuance(CLIENT_ASSET);

	let mut trader = Trader::new();
	let change = trader.buy_weight(weight_worth_of(fee), holding_asset, &xcm_context()).unwrap();
	assert_eq!(&change, &holding_change);

	assert_eq!(trader.total_fee.peek(), fee);
	assert_eq!(trader.last_fee_asset, Some(create_asset_id(CLIENT_ASSET)));

	let refund = trader.refund_weight(weight_worth_of(refund1), &xcm_context());
	assert_eq!(refund.as_ref(), Some(&refund_asset));

	assert_eq!(trader.total_fee.peek(), fee - refund1);
	assert_eq!(trader.last_fee_asset, Some(create_asset_id(CLIENT_ASSET)));

	assert_eq!(trader.refund_weight(weight_worth_of(refund2), &xcm_context()), None);

	assert_eq!(trader.total_fee.peek(), fee - refund1);
	assert_eq!(trader.last_fee_asset, Some(create_asset_id(CLIENT_ASSET)));

	assert_eq!(Fungibles::total_issuance(TARGET_ASSET), target_total);
	assert_eq!(Fungibles::total_issuance(CLIENT_ASSET), client_total);
}
```
