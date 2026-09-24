[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** bridges/snowbridge/pallets/outbound-queue/src/lib.rs (L411-418)
```rust
		// 1 DOT has 10 digits of precision
		// 1 KSM has 12 digits of precision
		// 1 ETH has 18 digits of precision
		pub(crate) fn convert_from_ether_decimals(value: u128) -> T::Balance {
			let decimals = ETHER_DECIMALS.saturating_sub(T::Decimals::get()) as u32;
			let denom = 10u128.saturating_pow(decimals);
			value.checked_div(denom).expect("divisor is non-zero; qed").into()
		}
```

**File:** bridges/snowbridge/primitives/outbound-queue/src/v1/message.rs (L100-130)
```rust
	/// Transfer ERC20 tokens
	UnlockNativeToken {
		/// ID of the agent
		agent_id: H256,
		/// Address of the ERC20 token
		token: H160,
		/// The recipient of the tokens
		recipient: H160,
		/// The amount of tokens to transfer
		amount: u128,
	},
	/// Register foreign token from Polkadot
	RegisterForeignToken {
		/// ID for the token
		token_id: H256,
		/// Name of the token
		name: Vec<u8>,
		/// Short symbol for the token
		symbol: Vec<u8>,
		/// Number of decimal places
		decimals: u8,
	},
	/// Mint foreign token from Polkadot
	MintForeignToken {
		/// ID for the token
		token_id: H256,
		/// The recipient of the newly minted tokens
		recipient: H160,
		/// The amount of tokens to mint
		amount: u128,
	},
```

**File:** substrate/frame/psm/src/lib.rs (L1621-1644)
```rust
		/// Convert an amount denominated in internal units into external-asset units.
		///
		/// Inverse of [`Self::external_to_internal`]. Floor-divides when internal has more
		/// decimals, multiplies up when it has fewer.
		pub(crate) fn internal_to_external(
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
					Ok(amount.checked_div(&factor).unwrap_or_else(BalanceOf::<T>::zero))
				},
				Greater => {
					let diff = (ext_decimals - internal_decimals) as u32;
					let factor = Self::pow10(diff)?;
					amount.checked_mul(&factor).ok_or(Error::<T>::ConversionOverflow)
				},
			}
		}
```

**File:** prdoc/stable2606/pr_11819.prdoc (L14-16)
```text
    - `mint` and `redeem` use round-trip rounding. Truncation dust stays in the
      caller's wallet on both paths (symmetric behavior), no value is trapped
      in the reserve and no hidden dust is routed to the fee destination.
```

**File:** substrate/frame/psm/src/tests.rs (L2575-2604)
```rust
	#[test]
	fn mint_scale_down_dai_leaves_dust_with_user() {
		new_test_ext().execute_with(|| {
			register_external_asset_with_weight(DAI_MOCK_ASSET_ID, Permill::from_percent(100));
			set_zero_fees(DAI_MOCK_ASSET_ID);

			// 100 DAI + 123 wei. internal equivalent = 100 * 10^6 = 10^8 (= MinSwapAmount).
			let dai_raw = 100 * DAI_UNIT + 123;
			let effective_dai = 100 * DAI_UNIT; // truncated to round-trip boundary
			let expected_internal = 100 * INTERNAL_UNIT;
			let alice_before = get_asset_balance(DAI_MOCK_ASSET_ID, ALICE);

			assert_ok!(Psm::mint(
				RuntimeOrigin::signed(ALICE),
				INTERNAL_ASSET_ID,
				DAI_MOCK_ASSET_ID,
				dai_raw,
				Permill::zero()
			));

			// Only effective amount left the user; dust (123 wei) stays.
			assert_eq!(get_asset_balance(DAI_MOCK_ASSET_ID, ALICE), alice_before - effective_dai);
			assert_eq!(get_asset_balance(DAI_MOCK_ASSET_ID, psm_account()), effective_dai);
			assert_eq!(get_asset_balance(INTERNAL_ASSET_ID, ALICE), expected_internal);
			assert_eq!(
				PsmDebt::<Test>::get(INTERNAL_ASSET_ID, DAI_MOCK_ASSET_ID),
				expected_internal
			);
		});
	}
```

**File:** prdoc/stable2509/pr_9357.prdoc (L1-8)
```text
title: "Fix dust balance handling in ETH transfers"

doc:
  - audience: Runtime Dev
    description: |-
      Fixed a bug in the eth-decimals implementation where ETH transfers were failing due to incorrect receiver dust balance handling. The condition for minting a new currency unit when transferring dust was checking `to_info.dust.saturating_add(dust) >= plank` which `to_info.dust` has been added twice, could lead to unexpected minting behavior.
      This fix ensures that ETH transfers work correctly, enabling proper operation of DeFi protocols like Uniswap on PolkaVM.

```
