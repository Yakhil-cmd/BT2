### Title
Fee payment via `pallet-asset-conversion-tx-payment` uses manipulable spot AMM price instead of a protected/TWAP price, allowing users to sandwich their own transaction-fee conversion - (File: substrate/frame/transaction-payment/asset-conversion-tx-payment/src/payment.rs)

### Summary
`ChargeAssetTxPayment`'s `SwapAssetAdapter::withdraw_fee`/`can_withdraw_fee` price the native-fee-equivalent amount of a user-chosen asset by calling `S::quote_price_tokens_for_exact_tokens` [1](#0-0) , which is backed by `pallet-asset-conversion`'s live pool reserves via `get_reserves`/`get_amount_in` [2](#0-1) . This is the exact same class of bug as the SpotHedgeBaseMaker sandwich report: a critical monetary calculation (here, the fee actually charged) is derived from an instantaneous, permissionlessly-manipulable AMM spot price, with no price band, TWAP, or oracle cross-check.

### Finding Description
Any signed account can permissionlessly call `pallet-asset-conversion::swap_exact_tokens_for_tokens`/`swap_tokens_for_exact_tokens` on the same pool that `pallet-asset-conversion-tx-payment` uses to price fees [3](#0-2) . The `ChargeAssetTxPayment` extension quotes the fee in the user-selected `asset_id` using `quote_price_tokens_for_exact_tokens(asset_id, A::get(), fee, true)`, computed strictly from the pool's current reserves at the moment `withdraw_fee` runs (`get_reserves` + `get_amount_in`, a pure constant-product formula, no TWAP or deviation cap) [4](#0-3) . Unlike `pallet-asset-conversion`'s normal swap calls (which have `amount_out_min`/`amount_in_max` slippage checks set by the *swapper*, not by the party being protected), there is nothing in the tx-payment flow analogous to Perpetual's price-band check that limits how far the pool price used for a fee conversion can deviate from a fair/oracle price.

This mirrors the reported root cause precisely: "the assumption is that the pool prices tokens properly... this assumption is incorrect, because an attacker can sandwich their own trade." Here the attacker's own "trade" is the fee-conversion swap embedded in `withdraw_fee`/`correct_and_deposit_fee`, and the sandwich is performed across the ordinary permissionless swap extrinsics in the same or adjacent blocks: skew the pool so `asset_id` is priced expensive relative to the native fee asset → submit/pay the fee-charged extrinsic (fee computed off the skewed reserves, so a much smaller amount of `asset_id` is debited for the same native-fee target) → swap back to restore the pool, recovering most of the temporarily-donated liquidity minus AMM fees.

### Impact Explanation
Every fee paid via `ChargeAssetTxPayment` with a non-native `asset_id` is subject to this manipulation. An attacker who also controls (or is a large LP of) the relevant asset-conversion pool can systematically underpay transaction fees, and — more importantly — because `withdraw_fee` withdraws `asset_fee` of the *user's* asset and swaps it into the pool for the exact native fee, a skewed pool lets the attacker extract pool liquidity: they donate value to the pool during the "spike" swap, receive a cheap fee quote, and reclaim the donated liquidity by reversing the spike. This is a direct value-transfer from the liquidity pool (and its LPs) to the attacker, structurally identical to the reported Medium-severity SpotHedgeBaseMaker issue. Severity is bounded similarly to the report: value extractable is limited by pool depth, LP fee, and how far the attacker is willing/able to skew the price within one block/transaction window, so this is a Medium-class economic/pricing-oracle issue, not an unbacked-issuance or governance-bypass bug.

### Likelihood Explanation
Likelihood is moderate: it requires (a) a runtime that wires `pallet-asset-conversion-tx-payment`'s `SwapAssetAdapter` (or the `AssetConversionAdapter`) to a `pallet-asset-conversion` pool that is thinly liquid relative to fee sizes, and (b) an attacker willing to spend gas/fees on the skew+restore swaps and accept AMM trading fees as cost. It does not require any privileged role — all calls involved (`swap_exact_tokens_for_tokens`, paying a fee with a custom `asset_id`) are ordinary signed extrinsics available to any user, matching the report's "no privileged role" constraint. I was not able to fully confirm from the index which shipped runtimes (e.g. Asset Hub) actually configure `ChargeAssetTxPayment`/`SwapAssetAdapter` against a public/permissionless asset-conversion pool in production versus a governance-curated one, nor whether any additional slippage bound is enforced by runtime-side pool selection policy; this would need to be verified directly in the runtime configuration (e.g. `asset-hub-westend`/`asset-hub-rococo` `Runtime` `impl` blocks) before treating this as conclusively exploitable at current mainnet liquidity levels.

### Recommendation
- Do not rely on the instantaneous constant-product spot price for fee-asset conversion. Use a time-weighted average price (TWAP) over multiple blocks, or bound the deviation between the spot quote and a longer-window reference price before accepting it in `withdraw_fee`/`can_withdraw_fee`.
- Alternatively, restrict which asset/pool pairs are eligible for `ChargeAssetTxPayment` to governance-whitelisted, sufficiently deep pools, and/or cap the maximum fraction of pool reserves a single fee-conversion swap may consume per block.
- Consider requiring `withdraw_fee` to compare the quoted fee against a recent block's quote and reject/clamp swaps that deviate beyond a configured tolerance, analogous to Perpetual's price-band mitigation.

### Proof of Concept
Not executed. A full reproduction would require a Rust/FRAME integration test (using the existing `asset-conversion-tx-payment` test harness, e.g. `setup_lp` in `substrate/frame/transaction-payment/asset-conversion-tx-payment/src/tests.rs`) that: (1) creates a thin `Native/AssetX` pool via `AssetConversion::create_pool`/`add_liquidity`; (2) has the attacker call `AssetConversion::swap_exact_tokens_for_tokens` to skew reserves; (3) submits a `ChargeAssetTxPayment::validate_and_prepare` extrinsic paying fees in `AssetX` and records the debited `fee_in_asset` via `AssetConversion::quote_price_tokens_for_exact_tokens`, comparing it against the unskewed baseline (as already partially demonstrated by `transaction_payment_in_asset_possible` and related tests showing the fee-in-asset amount is a direct function of pool reserves) [5](#0-4) ; (4) has the attacker swap back and measures net asset recovered minus LP fees. This test was not run in this session — the analysis is based on static code review only, and PoC execution/results are outstanding.

### Citations

**File:** substrate/frame/transaction-payment/asset-conversion-tx-payment/src/payment.rs (L119-146)
```rust
	fn withdraw_fee(
		who: &T::AccountId,
		_call: &T::RuntimeCall,
		_dispatch_info: &DispatchInfoOf<<T>::RuntimeCall>,
		asset_id: Self::AssetId,
		fee: Self::Balance,
		_tip: Self::Balance,
	) -> Result<Self::LiquidityInfo, TransactionValidityError> {
		if asset_id == A::get() {
			// The `asset_id` is the target asset, we do not need to swap.
			let fee_credit = F::withdraw(
				asset_id.clone(),
				who,
				fee,
				Precision::Exact,
				Preservation::Preserve,
				Fortitude::Polite,
			)
			.map_err(|_| InvalidTransaction::Payment)?;

			return Ok((fee_credit, fee));
		}

		// Quote the amount of the `asset_id` needed to pay the fee in the asset `A`.
		let asset_fee =
			S::quote_price_tokens_for_exact_tokens(asset_id.clone(), A::get(), fee, true)
				.filter(|asset_fee| !asset_fee.is_zero())
				.ok_or(InvalidTransaction::Payment)?;
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L521-545)
```rust
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
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1291-1316)
```rust
		/// Leading to an amount at the end of a `path`, get the required amounts in.
		pub(crate) fn balance_path_from_amount_out(
			amount_out: T::Balance,
			path: Vec<T::AssetKind>,
		) -> Result<BalancePath<T>, DispatchError> {
			let mut balance_path: BalancePath<T> = Vec::with_capacity(path.len());
			let mut amount_in: T::Balance = amount_out;

			let mut iter = path.into_iter().rev().peekable();
			while let Some(asset2) = iter.next() {
				let asset1 = match iter.peek() {
					Some(a) => a,
					None => {
						balance_path.push((asset2, amount_in));
						break;
					},
				};
				let fee = Self::pool_fee_for(asset1, &asset2)?;
				let (reserve_in, reserve_out) = Self::get_reserves(asset1.clone(), asset2.clone())?;
				balance_path.push((asset2, amount_in));
				amount_in = Self::get_amount_in(fee, &amount_in, &reserve_in, &reserve_out)?;
			}
			balance_path.reverse();

			Ok(balance_path)
		}
```

**File:** substrate/frame/transaction-payment/asset-conversion-tx-payment/src/tests.rs (L244-256)
```rust
			setup_lp(asset_id, balance_factor);

			let fee_in_native = base_weight + tx_weight + len as u64;
			let input_quote = AssetConversion::quote_price_tokens_for_exact_tokens(
				NativeOrWithId::WithId(asset_id),
				NativeOrWithId::Native,
				fee_in_native,
				true,
			);
			assert_eq!(input_quote, Some(201));

			let fee_in_asset = input_quote.unwrap();
			assert_eq!(Assets::balance(asset_id, caller), balance);
```
