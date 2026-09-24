## Analysis: AMM sandwich attack analog in Polkadot SDK

The reported bug is about a DEX swap executed inside a user's transaction without slippage (`amountOutMin`) protection, allowing a sandwich attack. I searched the FRAME analog of an AMM — `pallet-asset-conversion` — and its consumers.

**`pallet-asset-conversion` itself is protected.** The dispatchable extrinsics `swap_exact_tokens_for_tokens` and `swap_tokens_for_exact_tokens` take mandatory `amount_out_min`/`amount_in_max` parameters and enforce them via `Error::ProvidedMinimumNotSufficientForSwap`/`ProvidedMaximumNotSufficientForSwap`, as shown at [1](#0-0)  and tested at [2](#0-1) . So user-initiated swaps are not analogous to the bug.

However, I found a genuine analog in `cumulus-primitives-utility`'s `SwapFirstAssetTrader`, an XCM `WeightTrader` that swaps a user's fee asset into a `Target` asset via `SwapCredit`, and refunds unused weight back at the end of message execution.

### Title
Unprotected zero-slippage refund swap in `SwapFirstAssetTrader::refund_weight` - (File: cumulus/primitives/utility/src/lib.rs)

### Summary
`SwapFirstAssetTrader::refund_weight` swaps the unused `Target` fee credit back into the original asset the user paid with, using `SwapCredit::swap_exact_tokens_for_tokens(..., None)` — passing `None` as `amount_out_min`, i.e. **no slippage protection at all**, unlike the `buy_weight` path which swaps for an exact output amount.

### Finding Description
`buy_weight` swaps the user's asset into the `Target` asset using `swap_tokens_for_exact_tokens` (exact-output, so the user pays a bounded, price-dependent input) [3](#0-2) . But `refund_weight`, which returns unused weight fee back to the user, swaps `Target` back to the original asset with:
```rust
let refund = self.total_fee.extract(refund_amount);
let refund = match SwapCredit::swap_exact_tokens_for_tokens(
    vec![Target::get(), refund_swap_asset],
    refund,
    None,
) {
``` [4](#0-3) 

Because `amount_out_min` is `None`, `pallet_asset_conversion`'s underlying `do_swap_exact_credit_tokens_for_tokens` skips the minimum-output check entirely (that check is only performed `if let Some(amount_out_min) = ...`), see [5](#0-4) . The swap will accept whatever output the AMM pool returns at execution time, no matter how small.

`SwapFirstAssetTrader` is wired into live/test parachain runtimes' XCM configs: `asset-hub-rococo`, `asset-hub-westend`, `penpal`, and `staking-async` parachain, confirmed by the grep hits in their `xcm_config.rs` files, and by `prdoc/stable2506/pr_8376.prdoc` which documents that `TakeFirstAssetTrader` was removed from AssetHub Westend/Rococo in favor of `SwapFirstAssetTrader`.

### Impact Explanation
An attacker who is not privileged can, within the same block, submit two ordinary signed `pallet_asset_conversion::swap_exact_tokens_for_tokens`/`swap_tokens_for_exact_tokens` extrinsics on the same `(Target, refund_swap_asset)` pool that a victim's XCM message will use for fee refund:
1. Front-run: heavily unbalance the pool by swapping a large amount of `refund_swap_asset` into `Target` (or vice versa), driving the price against the upcoming refund swap.
2. The victim's incoming XCM message executes `buy_weight` (protected, exact-output) then `refund_weight`, whose zero-slippage swap of the refund is executed at the attacker-manipulated price, returning far less of `refund_swap_asset` than the user is entitled to.
3. Back-run: reverse the initial swap to restore the pool and capture the difference as arbitrage profit, extracted from the victim's refund.

The loss is bounded by the size of `total_fee`/refund (i.e., XCM weight fees), so it is not an unbounded issuance/theft bug, but it is a measurable, deterministic loss of user funds caused by a missing check that exists elsewhere in the same file (`buy_weight`) but was omitted in `refund_weight`.

### Likelihood Explanation
Requires: (a) a shallow/thinly-liquid `(Target, refund_swap_asset)` pool in `pallet-asset-conversion`, (b) a victim XCM message that pays fees in a non-`Target` asset and leaves an unused-weight refund, and (c) the attacker being able to place manipulating swaps before/after the victim's message is executed in the same block — all of which are permissionless, ordinary user actions requiring no privileged role. This mirrors exactly the "rare conditions" caveat in the original report: it depends on pool liquidity/refund size but requires no special access.

### Recommendation
Thread a caller-supplied or configurably conservative `amount_out_min` (e.g., derived from `QuotePrice::quote_price_exact_tokens_for_tokens` with a tolerance, or reuse of `total_fee`/expected fair value) into the `refund_weight` swap instead of passing `None`, mirroring the protection already applied in `buy_weight`.

### Proof of Concept
No PoC was executed against a live network. The finding is based on static code comparison of the two swap call-sites within the same struct impl: `buy_weight` at [6](#0-5)  uses an exact-output amount (implicitly bounding the trade), while `refund_weight` at [7](#0-6)  passes `None`, which is provably unchecked per the pallet's `ensure!(amount_out_min.map_or(true, |a| amount_out >= a), ...)` logic at [8](#0-7) . A minimal local FRAME integration reproduction would extend the existing test harness in `cumulus/primitives/utility/src/tests/swap_first.rs` (which already sets up a mock `SwapCreditT`/pool, see [9](#0-8) ) to simulate a pool-price shift between `buy_weight` and `refund_weight` calls and assert the refunded amount falls below a fair-value tolerance — this was not executed as part of this analysis, only architecturally traced through source.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L994-1002)
```rust
			let path = Self::balance_path_from_amount_in(amount_in, path)?;

			let amount_out = path.last().map(|(_, a)| *a).ok_or(Error::<T>::InvalidPath)?;
			if let Some(amount_out_min) = amount_out_min {
				ensure!(
					amount_out >= amount_out_min,
					Error::<T>::ProvidedMinimumNotSufficientForSwap
				);
			}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1092-1097)
```rust
				let amount_out = path.last().map(|(_, a)| *a).ok_or(Error::<T>::InvalidPath)?;
				ensure!(
					amount_out_min.map_or(true, |a| amount_out >= a),
					Error::<T>::ProvidedMinimumNotSufficientForSwap
				);
				Ok((path, amount_out))
```

**File:** substrate/frame/asset-conversion/src/tests.rs (L1600-1612)
```rust
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
```

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

**File:** cumulus/primitives/utility/src/tests/swap_first.rs (L425-454)
```rust
		fn swap_exact_tokens_for_tokens(
			path: Vec<Self::AssetKind>,
			credit_in: Self::Credit,
			amount_out_min: Option<Self::Balance>,
		) -> Result<Self::Credit, (Self::Credit, DispatchError)> {
			ensure!(2 == path.len(), (credit_in, DispatchError::Unavailable));
			ensure!(
				credit_in.peek() >= amount_out_min.unwrap_or(Self::Balance::zero()),
				(credit_in, DispatchError::Unavailable)
			);
			let swap_res = SWAP.with(|b| b.borrow().get(&(path[0], path[1])).map(|v| *v));
			let pool_account = match swap_res {
				Some(a) => a,
				None => return Err((credit_in, DispatchError::Unavailable)),
			};
			let credit_out = match Fungibles::withdraw(
				path[1],
				&pool_account,
				credit_in.peek(),
				Exact,
				Preserve,
				Polite,
			) {
				Ok(c) => c,
				Err(_) => return Err((credit_in, DispatchError::Unavailable)),
			};
			Fungibles::resolve(&pool_account, credit_in)
				.map_err(|c| (c, DispatchError::Unavailable))?;
			Ok(credit_out)
		}
```
