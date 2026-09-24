[1](#0-0) [2](#0-1)

### Citations

**File:** substrate/frame/psm/src/lib.rs (L1600-1618)
```rust
		pub(crate) fn external_to_internal(
			amount: BalanceOf<T>,
			ext_decimals: u8,
			internal_decimals: u8,
		) -> Result<BalanceOf<T>, Error<T>> {
			use core::cmp::Ordering::*;
			match ext_decimals.cmp(&internal_decimals) {
				Equal => Ok(amount),
				Less => {
					let diff = (internal_decimals - ext_decimals) as u32;
					let factor = Self::pow10(diff)?;
					amount.checked_mul(&factor).ok_or(Error::<T>::ConversionOverflow)
				},
				Greater => {
					let diff = (ext_decimals - internal_decimals) as u32;
					let factor = Self::pow10(diff)?;
					Ok(amount.checked_div(&factor).unwrap_or_else(BalanceOf::<T>::zero))
				},
			}
```

**File:** substrate/frame/psm/src/tests.rs (L2939-2974)
```rust
	#[test]
	fn redeem_rejects_when_external_out_truncates_to_zero() {
		new_test_ext().execute_with(|| {
			register_external_asset_with_weight(USDX_ASSET_ID, Permill::from_percent(100));
			set_zero_fees(USDX_ASSET_ID);

			// Seed the PSM reserve and ALICE's internal balance with a prior mint.
			let usdx_raw = 10_000 * USDX_UNIT;
			assert_ok!(Psm::mint(
				RuntimeOrigin::signed(ALICE),
				INTERNAL_ASSET_ID,
				USDX_ASSET_ID,
				usdx_raw,
				Permill::zero()
			));

			// Configure an extreme redemption fee so `internal_net > 0` but falls
			// below one USDX raw unit (factor 10^4). With MinSwapAmount = 10^8
			// internal and a 99.9999% fee:
			//   fee      = mul_ceil(999_999 * 10^8 / 10^6) = 99_999_900
			//   internal_net = 10^8 - 99_999_900 = 100
			//   external = 100 / 10^4 = 0  ← genuine truncation, must reject.
			set_redemption_fee(USDX_ASSET_ID, Permill::from_parts(999_999));

			let redeem = 100 * INTERNAL_UNIT;
			assert_noop!(
				Psm::redeem(
					RuntimeOrigin::signed(ALICE),
					INTERNAL_ASSET_ID,
					USDX_ASSET_ID,
					redeem,
					Permill::from_parts(999_999)
				),
				Error::<Test>::AmountTooSmallAfterConversion
			);
		});
```
