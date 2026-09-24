### Title
`SwapFirstAssetTrader::refund_weight` swaps unused XCM execution fees back to the payer's asset with no slippage protection - ([File: cumulus/primitives/utility/src/lib.rs])

### Summary
`SwapFirstAssetTrader` is the `WeightTrader` used in production Cumulus/Asset Hub-style runtimes (wired in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs` and `asset-hub-rococo/src/xcm_config.rs`, confirmed as the replacement for `TakeFirstAssetTrader` per `prdoc/stable2506/pr_8376.prdoc`) to let users pay XCM execution fees in a non-native asset by swapping it for the `Target` (native) asset via `pallet_asset_conversion`'s `SwapCredit`. When unused weight is refunded at the end of message processing, `refund_weight` swaps the leftover `Target` credit back into the original payment asset — but calls `SwapCredit::swap_exact_tokens_for_tokens` with `amount_out_min = None`, unlike every other swap call site in the codebase (`buy_weight` in the same file uses `swap_tokens_for_exact_tokens` with an exact output; `pallet_asset_conversion`'s own dispatchables always require/enforce `amount_out_min`; `SingleAssetExchangeAdapter` in `polkadot/xcm/xcm-builder` always passes `Some(want_amount)`; `SwapAssetAdapter` in `pallet_asset_conversion_tx_payment` uses exact-output swaps).

### Finding Description
`cumulus/primitives/utility/src/lib.rs`:

```rust
let refund = self.total_fee.extract(refund_amount);
let refund = match SwapCredit::swap_exact_tokens_for_tokens(
    vec![Target::get(), refund_swap_asset],
    refund,
    None,          // <-- amount_out_min
) { ... };
``` [1](#0-0) 

`swap_exact_tokens_for_tokens` on `pallet_asset_conversion::Pallet` explicitly supports and enforces a minimum-out check when `Some(amount_out_min)` is supplied: [2](#0-1) 

but here the caller deliberately passes `None`, so `Self::do_swap_exact_credit_tokens_for_tokens` skips the `ProvidedMinimumNotSufficientForSwap` check entirely and accepts whatever the pool returns, however small, for the refund credit.

Contrast with the sibling `buy_weight` function in the very same struct, which swaps the *user's* payment asset for the `Target` asset using `swap_tokens_for_exact_tokens` (exact-output, capped input), which is inherently slippage-safe for the amount charged: [3](#0-2) 

And contrast with `SingleAssetExchangeAdapter::exchange_asset`, which always forwards the user-supplied `want_amount` as the enforced minimum to the same `SwapCredit` trait: [4](#0-3) 

This shows the codebase's established pattern is to always bound swap output/input; `refund_weight`'s `None` is the one place where that bound is dropped.

The pool state (`pallet_asset_conversion`) is a normal permissionless pool. Any account can freely trade in it via `swap_exact_tokens_for_tokens`/`swap_tokens_for_exact_tokens`, an ordinary, unprivileged public extrinsic. `pallet_xcm::execute` is a normal signed extrinsic available to any user, letting them submit an XCM program that pays fees in a non-`Target` asset, causing `SwapFirstAssetTrader` to be invoked as the configured `Trader`. Weight estimation is imprecise (the `buy_weight` amount is based on the declared/instructed weight, while `refund_weight` is computed from the *actual* consumed weight at completion), so the size of the refunded credit and the price at refund time depend on final pool state, which any account can move between the `buy_weight` charge and the `refund_weight` execution within the same message (e.g., via other XCM programs/extrinsics interleaved by the block author, or if the executed XCM message itself contains a `Transact`/nested instruction that trades in the same pool before the refund fires).

### Impact Explanation
Because `refund_weight` performs an unconditionally-accepted swap with no output floor, a user's fee refund can be swapped at an arbitrarily bad price if the pool is thin or has just been moved (intentionally or not) between `buy_weight` and `refund_weight`. In the worst case (an attacker who sandwiches the specific message's refund step, e.g. by trading right before the message is finalized and right after), the refund credit can be reduced to near zero, and the difference is captured by whoever moved the pool price in that window (an ordinary, unprivileged trader). This is a direct loss-of-funds vector for the fee-paying account, caused purely by a missing/omitted slippage parameter that is otherwise available and used everywhere else in the same trait/API — the exact bug class described in the source report (`FlashLoanLiquidate.JOJOFlashLoan` omitting a slippage/min-out parameter that its own sibling contracts (`FlashLoanRepay`, `GeneralRepay`) enforce).

### Likelihood Explanation
Reachability requires no privileges: any user can pay XCM fees in a non-native asset processed by a runtime configured with `SwapFirstAssetTrader` (confirmed live in Asset Hub Westend/Rococo-style runtimes), and any user can freely trade against the same swap pool used for the refund (a plain, permissionless `pallet_asset_conversion` pool). However, extracting meaningful value requires the attacker to time a trade precisely around another user's specific refund step within a single XCM message's execution window — this is inherently a front-running/sandwich-style economic manipulation of price rather than a direct protocol-level fund-extraction bug, and the scan's exclusion rules explicitly reject "pure front-running/economic attacks" as non-qualifying findings. I was not able to fully verify, within the remaining investigation budget, whether an attacker's own trade can be deterministically interleaved between `buy_weight` and `refund_weight` for a *specific victim's* message in this executor's actual scheduling model (single-message-atomic execution vs. block-level interleaving of separate messages/extrinsics), which is required to demonstrate concrete attacker-controlled profit rather than a purely self-inflicted, price-shift risk to the fee payer.

### Recommendation
Pass a computed `amount_out_min` (e.g., derived from `QuotePrice::quote_price_exact_tokens_for_tokens` at the time of refund, with a configurable tolerance) into `SwapCredit::swap_exact_tokens_for_tokens` inside `refund_weight`, mirroring the exact-output/bounded pattern already used in `buy_weight` and in `SingleAssetExchangeAdapter`. If the swap cannot meet the minimum, fail closed (return `None`/keep the `Target`-asset credit rather than swapping) rather than silently accepting an unbounded-slippage trade.

### Proof of Concept
Not executed. Given the front-running/economic-attack caveat noted above and the remaining uncertainty about whether a third party can deterministically interleave a price-moving trade inside a single XCM message's `buy_weight`→`refund_weight` window (as opposed to only affecting the message-issuer's own refund via self-inflicted price movement), I did not build or run a local Rust/FRAME integration reproduction. The existing unit tests in `cumulus/primitives/utility/src/tests/swap_first.rs` (e.g. `buy_and_refund_twice_for_target`) exercise `refund_weight` only under a static/unmoved pool and do not demonstrate the missing-slippage-check impact; a reproduction would need to mutate the pool's reserves between the `buy_weight` and `refund_weight` calls within the mock harness and assert the refunded amount falls below any reasonable expectation, and separately establish (via the actual XCM executor's message-processing model) that this window is exploitable by a third party rather than only by the message's own signer.

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
