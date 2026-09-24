Confirmed: `prepare` (pre-dispatch, calling `withdraw_fee`) and `post_dispatch_details` (post-dispatch, calling `correct_and_deposit_fee`) in `ChargeAssetTxPayment` bracket the actual dispatch of the user's own `RuntimeCall`, and each independently re-reads the AMM pool's spot reserves via `QuotePrice`/`SwapCredit` at the moment they execute. This is a real, demonstrable analog to the Curve `AggregateStablePrice.price()` issue: a value derived from mutable pool reserves (analogous to `pool_supply/totalSupply`) is read twice at different points of one atomic transaction, and the user's own dispatched call can shift those reserves in between, letting them tilt the second (refund) read in their favor.

### Title
Manipulable AMM Pool-Reserve Price Read in `SwapAssetAdapter::correct_and_deposit_fee` Enables Fee-Refund Value Extraction - ([File: substrate/frame/transaction-payment/asset-conversion-tx-payment/src/payment.rs])

### Summary
`pallet-asset-conversion-tx-payment`'s `SwapAssetAdapter` pays transaction fees in a non-native asset by swapping against a `pallet-asset-conversion` liquidity pool. The fee is withdrawn (asset→native swap) in `withdraw_fee` during `prepare` (pre-dispatch), and any overpaid refund is swapped back (native→asset) in `correct_and_deposit_fee` during `post_dispatch_details`, using `S::quote_price_exact_tokens_for_tokens` / `S::swap_exact_tokens_for_tokens` against the pool's *live* reserves at that moment [1](#0-0) . Between these two reads, the user's own dispatched `RuntimeCall` executes and can freely trade against the exact same pool [2](#0-1) [3](#0-2) .

### Finding Description
`quote_price_exact_tokens_for_tokens`/`quote_price_tokens_for_exact_tokens` compute prices directly from the pool account's current asset balances (`get_reserves`), with no time-weighting or manipulation resistance, and the doc comment explicitly warns the quote is "only guaranteed if no other swaps are made after the price is quoted" [4](#0-3)  and [5](#0-4) .

In `SwapAssetAdapter`:
- `withdraw_fee` (pre-dispatch) quotes and swaps `asset_id`→`A` (native) reserves at their state before the user's call runs [6](#0-5) .
- `correct_and_deposit_fee` (post-dispatch) re-quotes and swaps the leftover native refund back into `asset_id`, using whatever reserves exist *after* the user's call has executed [7](#0-6) .

Since the extrinsic author fully controls the `RuntimeCall` dispatched between these two points, and that call can itself be an `AssetConversion::swap_*` call operating on the identical `(A, asset_id)` pool, the attacker can deliberately unbalance the pool's reserves (e.g., push a large amount of `asset_id` in / pull `A` out) immediately before `correct_and_deposit_fee` executes. Because `get_amount_out` is a convex function of reserves (`amount_out = reserve_out * amount_in / (reserve_in + amount_in)`), driving `reserve_in` (native, `A`) down and `reserve_out` (`asset_id`) up inflates the quoted/swapped refund amount for the same fixed `refund_amount` of native, extracting value from the pool (i.e., from other liquidity providers) beyond what an honest, unmanipulated AMM trade would yield. No flashloan primitive is required — the whole sequence (fee withdrawal, price-shifting swap, refund swap) happens atomically within one signed extrinsic's pre-dispatch/dispatch/post-dispatch lifecycle, which is the direct on-chain analog of the Curve report's "attacker manipulates the price-determining pool state with their own capital within one atomic operation" root cause.

### Impact Explanation
This allows a normal, unprivileged signed-extrinsic sender who pays fees via `ChargeAssetTxPayment` with a non-native `asset_id` to extract value from the underlying `pallet-asset-conversion` liquidity pool at the expense of its liquidity providers, by manipulating reserves between the pre-dispatch fee swap and the post-dispatch refund swap. The magnitude is bounded by the refund size (over-estimated weight fee) and the depth of the pool, and the attacker still pays the AMM's LP fee on their manipulation trade, so net profitability depends on pool depth/refund size — this is a value-extraction/economic-manipulation issue rather than unbounded fund theft, consistent with the source report's classification as Medium severity for the analogous Curve issue.

### Likelihood Explanation
Any account that (a) opts to pay fees in a non-native asset via `ChargeAssetTxPayment`, and (b) the runtime wires `SwapAssetAdapter` as `OnChargeAssetTransaction`, and (c) is permitted to include a swap call against the same fee-asset/native pool as part of its own extrinsic (e.g., via a direct `pallet_asset_conversion::swap_exact_tokens_for_tokens` call, or nested inside `pallet_utility::batch`) can attempt this. Whether it is currently *wired* in a shipped production runtime (as opposed to `AssetConversionAdapter`, an alternate `OnChargeAssetTransaction` implementation) was not confirmed within the available context/index — this determines actual current exploitability on a live chain and needs verification.

### Recommendation
Do not re-read live pool spot-reserves for the post-dispatch refund swap; instead cache the effective exchange rate (or the specific reserve state) used for `withdraw_fee` and reuse a consistent rate/tolerance for `correct_and_deposit_fee`, or bound the allowed refund-swap slippage relative to the pre-dispatch quote. Alternatively, disallow (or transactionally isolate) calls that mutate the same pool used for fee payment within the extrinsic's own dispatched call, or require the refund swap to use a TWAP-style price rather than instantaneous reserves.

### Proof of Concept
Not executed against a running node. This is a code-flow analysis based on: `withdraw_fee` (pre-dispatch) [8](#0-7) , extrinsic dispatch occurring between `prepare` and `post_dispatch_details` [9](#0-8) , and `correct_and_deposit_fee` (post-dispatch) re-quoting against live reserves [7](#0-6) . A concrete numeric PoC (constructing exact reserve values, refund size, and profit calculation net of LP fees) and confirmation that a production runtime actually wires `SwapAssetAdapter` (vs. `AssetConversionAdapter`) for `OnChargeAssetTransaction` were not completed — these require a local FRAME integration test harness (mock runtime with `pallet-asset-conversion` + `pallet-asset-conversion-tx-payment` configured with `SwapAssetAdapter`, and a dispatched call performing the intervening swap) to fully validate profitability, which was not run in this session.

### Citations

**File:** substrate/frame/transaction-payment/asset-conversion-tx-payment/src/payment.rs (L119-176)
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

		// Withdraw the `asset_id` credit for the swap.
		let asset_fee_credit = F::withdraw(
			asset_id.clone(),
			who,
			asset_fee,
			Precision::Exact,
			Preservation::Preserve,
			Fortitude::Polite,
		)
		.map_err(|_| InvalidTransaction::Payment)?;

		let (fee_credit, change) = match S::swap_tokens_for_exact_tokens(
			vec![asset_id, A::get()],
			asset_fee_credit,
			fee,
		) {
			Ok((fee_credit, change)) => (fee_credit, change),
			Err((credit_in, _)) => {
				defensive!("Fee swap should pass for the quoted amount");
				let _ = F::resolve(who, credit_in).defensive_proof("Should resolve the credit");
				return Err(InvalidTransaction::Payment.into());
			},
		};

		// Since the exact price for `fee` has been quoted, the change should be zero.
		ensure!(change.peek().is_zero(), InvalidTransaction::Payment);

		Ok((fee_credit, asset_fee))
	}
```

**File:** substrate/frame/transaction-payment/asset-conversion-tx-payment/src/payment.rs (L259-286)
```rust
		// refund is non zero and `who`'s fee `asset_id` is not the target asset.

		// check if the refund amount can be swapped back into `who`'s fee `asset_id`.
		let refund_asset_amount =
			S::quote_price_exact_tokens_for_tokens(A::get(), asset_id.clone(), refund_amount, true)
				// No refund given if it cannot be swapped back.
				.unwrap_or(Zero::zero());

		// `fee_paid` cannot be swapped back into `who`'s fee `asset_id` or the refund amount cannot
		// be deposited into `who`'s fee `asset_id`, exit without refund.
		if refund_asset_amount.is_zero() ||
			!matches!(
				F::can_deposit(asset_id.clone(), who, refund_asset_amount, Provenance::Extant),
				DepositConsequence::Success
			) {
			let (tip, fee) = fee_paid.split(tip);
			OU::on_unbalanceds(Some(fee).into_iter().chain(Some(tip)));
			return Ok(fee_asset_amount);
		}

		// swap the refund amount back into `who`'s fee `asset_id`.

		let (refund, adjusted_paid) = fee_paid.split(refund_amount);

		let (fee_asset_amount, adjusted_paid) = match S::swap_exact_tokens_for_tokens(
			vec![A::get(), asset_id],
			refund,
			Some(refund_asset_amount),
```

**File:** substrate/frame/transaction-payment/asset-conversion-tx-payment/src/lib.rs (L327-360)
```rust
	fn prepare(
		self,
		val: Self::Val,
		_origin: &<T::RuntimeCall as Dispatchable>::RuntimeOrigin,
		call: &T::RuntimeCall,
		info: &DispatchInfoOf<T::RuntimeCall>,
		_len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		match val {
			Val::Charge { tip, who, fee } => {
				// Mutating call of `withdraw_fee` to actually charge for the transaction.
				let (_fee, initial_payment) = self.withdraw_fee(&who, call, info, fee)?;
				Ok(Pre::Charge { tip, who, initial_payment, weight: self.weight(call) })
			},
			Val::NoCharge => Ok(Pre::NoCharge { refund: self.weight(call) }),
		}
	}

	fn post_dispatch_details(
		pre: Self::Pre,
		info: &DispatchInfoOf<T::RuntimeCall>,
		post_info: &PostDispatchInfoOf<T::RuntimeCall>,
		len: usize,
		_result: &DispatchResult,
	) -> Result<Weight, TransactionValidityError> {
		let (tip, who, initial_payment, extension_weight) = match pre {
			Pre::Charge { tip, who, initial_payment, weight } => {
				(tip, who, initial_payment, weight)
			},
			Pre::NoCharge { refund } => {
				// No-op: Refund everything
				return Ok(refund);
			},
		};
```

**File:** substrate/frame/asset-conversion/src/swap.rs (L116-120)
```rust
/// Trait providing methods to quote swap prices between asset classes.
///
/// The quoted price is only guaranteed if no other swaps are made after the price is quoted and
/// before the target swap (e.g., the swap is made immediately within the same transaction).
pub trait QuotePrice {
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1499-1514)
```rust
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
