Based on my research, I found a genuine analog to the DeliHook rounding-down fee bug in `pallet-asset-conversion`'s liquidity withdrawal fee calculation.

### Title
Liquidity withdrawal fee rounds down to zero, letting LPs split withdrawals to avoid paying `LiquidityWithdrawalFee` - (File: `substrate/frame/asset-conversion/src/lib.rs`)

### Summary
`Pallet::do_remove_liquidity` computes the withdrawal fee as `T::LiquidityWithdrawalFee::get() * lp_token_burn`, using `Permill`'s standard `Mul` implementation, which truncates (`floor`) the result. [1](#0-0)  This mirrors the DeliHook bug: `baseFeeSpecified = amount * feeRate / 1e6` truncated instead of rounded up. Any LP can split a single large `remove_liquidity` call into many small ones, each falling below the rounding threshold, and pay zero (or a reduced) withdrawal fee in total compared to one large withdrawal of the same aggregate size.

### Finding Description
`do_remove_liquidity` is reachable via the public, unprivileged, signed extrinsic `AssetConversion::remove_liquidity` (any LP-token holder can call it). The fee line:
```
let withdrawal_fee_amount = T::LiquidityWithdrawalFee::get() * lp_token_burn;
let lp_redeem_amount = lp_token_burn.saturating_sub(withdrawal_fee_amount);
``` [2](#0-1) 
`Permill * Balance` uses integer division that rounds toward zero (floor), the same rounding direction identified as the root cause in the DeliHook report. If `lp_token_burn * fee_permill_value < 1_000_000` (i.e., `lp_token_burn < ACCURACY / fee_ppm`), `withdrawal_fee_amount` truncates to `0`, and the LP redeems `lp_redeem_amount == lp_token_burn` with no fee charged.

Meanwhile the resulting asset amounts, `amount1 = mul_div(lp_redeem_amount, reserve1, total_supply)` and `amount2` analogously, only need to be non-zero to pass the `AssetOneWithdrawalDidNotMeetMinimum` / `AssetTwoWithdrawalDidNotMeetMinimum` checks. [3](#0-2)  In pools where `reserve/total_supply` is large, a small `lp_token_burn` still yields non-zero `amount1`/`amount2`, so the checks pass even though the fee rounded to zero. By repeating `remove_liquidity` with `lp_token_burn` chunks sized just under the rounding threshold, an LP can fully exit a position while paying an aggregate fee far below (in the extreme, zero) what a single withdrawal of the same total size would incur — the exact "swap in a loop to avoid fee rounding" pattern described in the report, just applied to `remove_liquidity` instead of a swap.

This differs from the AMM swap fee (`get_amount_out`/`get_amount_in`), which bakes the fee directly into the constant-product curve and additionally rounds `get_amount_in` up via `+1`. [4](#0-3)  That path is not vulnerable to this class of bug (already patched per PR `pr_11804`/`pr_11795` for the swap and quote paths). The `LiquidityWithdrawalFee` is a separate, standalone `Permill * Balance` multiplication that was not similarly hardened.

### Impact Explanation
The impact is bounded and low. `LiquidityWithdrawalFee` currently defaults to `0%` in every runtime I found configured in-repo (`substrate/bin/node/runtime`, asset-hub, penpal, mock configs all set `Permill::from_percent(0)`), so in practice no production runtime charges this fee today — the vulnerable code path is dormant unless a runtime opts into a non-zero withdrawal fee via `AdminOrigin`/config. If a runtime did configure a non-zero fee, the loss is limited to the LP's own foregone fee contribution (an LP avoiding paying itself less to a "fee sink"), not third-party fund theft, and requires many small transactions bounded by weight/fee costs of `remove_liquidity` — an economic, gas-cost-bounded scenario similar in spirit to the original report but with materially smaller stakes because it only affects the withdrawal-fee sink, not a swap fee paid to LPs by external traders.

### Likelihood Explanation
Low likelihood in current deployed configurations because `LiquidityWithdrawalFee` is uniformly `0` in every runtime instance found in the codebase, making this dormant by default. It would only become exploitable if a runtime governance/`AdminOrigin` sets a non-zero `LiquidityWithdrawalFee`, and even then requires the attacker to hold LP tokens and be willing to pay repeated transaction fees to fragment withdrawals below the rounding threshold.

### Recommendation
Round the withdrawal fee up (e.g., using `Permill::mul_ceil` semantics, or `saturating_reciprocal_mul_ceil`/equivalent ceiling multiplication) instead of the default floor-rounding `Mul` operator, consistent with the approach already used for `pallet-psm`'s minting/redemption fees, which explicitly documents using `mul_ceil` "ensuring the protocol never undercharges." [5](#0-4) 

### Proof of Concept
I could not execute a live reproduction (no filesystem/terminal access in this session). Based on static analysis:
- Guard checked and found insufficient: `!amount1.is_zero() && amount1 >= amount1_min_receive` does not verify the withdrawal fee itself is non-zero. [6](#0-5) 
- Deployment evidence: all in-repo runtime configs currently set `LiquidityWithdrawalFee = Permill::from_percent(0)` (`substrate/bin/node/runtime/src/lib.rs:1973`, asset-hub-westend, penpal, and pallet mocks), meaning the bug is currently inert but would activate if a runtime configured a non-zero value.
- A concrete reproduction would require a local integration test (using the existing `pallet-asset-conversion` mock/test harness) that: (1) sets `LiquidityWithdrawalFee` to a non-zero `Permill`, (2) adds liquidity to create a pool with a large `reserve/total_supply` ratio, (3) calls `remove_liquidity` repeatedly with `lp_token_burn` values below `ACCURACY / fee_ppm`, and (4) asserts the summed `withdrawal_fee` events equal zero (or less than the fee on an equivalent single large withdrawal). I was not able to run this test in this session; this PoC is described but not executed.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L913-929)
```rust
			let (reserve1, reserve2) = Self::get_reserves(asset1.clone(), asset2.clone())?;

			let total_supply = T::PoolAssets::total_issuance(pool.lp_token.clone());
			let withdrawal_fee_amount = T::LiquidityWithdrawalFee::get() * lp_token_burn;
			let lp_redeem_amount = lp_token_burn.saturating_sub(withdrawal_fee_amount);

			let amount1 = Self::mul_div(&lp_redeem_amount, &reserve1, &total_supply)?;
			let amount2 = Self::mul_div(&lp_redeem_amount, &reserve2, &total_supply)?;

			ensure!(
				!amount1.is_zero() && amount1 >= amount1_min_receive,
				Error::<T>::AssetOneWithdrawalDidNotMeetMinimum
			);
			ensure!(
				!amount2.is_zero() && amount2 >= amount2_min_receive,
				Error::<T>::AssetTwoWithdrawalDidNotMeetMinimum
			);
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1443-1462)
```rust
			let fee_complement = fee.left_from_one().deconstruct();
			let numerator = reserve_in
				.checked_mul(&amount_out)
				.ok_or(Error::<T>::Overflow)?
				.checked_mul(&T::HigherPrecisionBalance::from(Permill::ACCURACY))
				.ok_or(Error::<T>::Overflow)?;

			let denominator = reserve_out
				.checked_sub(&amount_out)
				.ok_or(Error::<T>::Overflow)?
				.checked_mul(&T::HigherPrecisionBalance::from(fee_complement))
				.ok_or(Error::<T>::Overflow)?;

			let result = numerator
				.checked_div(&denominator)
				.ok_or(Error::<T>::Overflow)?
				.checked_add(&One::one())
				.ok_or(Error::<T>::Overflow)?;

			result.try_into().map_err(|_| Error::<T>::Overflow)
```

**File:** substrate/frame/psm/src/lib.rs (L670-674)
```rust
		/// Transfers `external_amount` of `external_asset` from the caller to the
		/// `internal_asset`'s PSM reserve account, then mints `internal_asset` to the
		/// caller minus the minting fee. The fee is calculated using ceiling rounding
		/// (`mul_ceil`), ensuring the protocol never undercharges. The fee is
		/// transferred to [`PsmInfo::fee_destination`] of the targeted instance.
```
