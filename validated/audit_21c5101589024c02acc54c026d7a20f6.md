[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** substrate/frame/psm/src/lib.rs (L713-726)
```rust
			let external = ExternalAssets::<T>::get(&internal_asset, &external_asset)
				.ok_or(Error::<T>::UnsupportedAsset)?;
			ensure!(external.status.allows_minting(), Error::<T>::MintingStopped);

			let ext_decimals = external.decimals;
			let internal_decimals = info.internal_decimals;

			let internal_equivalent =
				Self::external_to_internal(external_amount, ext_decimals, internal_decimals)?;
			ensure!(!internal_equivalent.is_zero(), Error::<T>::AmountTooSmallAfterConversion);
			ensure!(internal_equivalent >= info.min_swap_amount, Error::<T>::BelowMinimumSwap);

			let effective_external =
				Self::internal_to_external(internal_equivalent, ext_decimals, internal_decimals)?;
```

**File:** substrate/frame/psm/src/lib.rs (L1600-1619)
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
		}
```

**File:** substrate/frame/psm/src/tests.rs (L1108-1130)
```rust
	#[test]
	fn add_external_asset_uses_recorded_internal_decimals_after_metadata_changes() {
		new_test_ext().execute_with(|| {
			let new_asset = 99u32;
			create_asset_with_metadata(new_asset);

			assert_ok!(Assets::set_metadata(
				RuntimeOrigin::signed(ALICE),
				INTERNAL_ASSET_ID,
				b"Internal Asset".to_vec(),
				b"INTERNAL".to_vec(),
				31
			));

			assert_ok!(Psm::add_external_asset(
				RuntimeOrigin::root(),
				INTERNAL_ASSET_ID,
				new_asset
			));
			let stored = crate::ExternalAssets::<Test>::get(INTERNAL_ASSET_ID, new_asset)
				.expect("external present");
			assert_eq!(stored.decimals, 6);
		});
```

**File:** substrate/frame/psm/src/tests.rs (L2979-3005)
```rust
	#[test]
	fn mint_uses_snapshot_when_asset_decimals_drift() {
		new_test_ext().execute_with(|| {
			register_external_asset_with_weight(USDX_ASSET_ID, Permill::from_percent(100));
			set_zero_fees(USDX_ASSET_ID);

			// Owner (ALICE) unilaterally changes USDX decimals from 2 -> 4.
			assert_ok!(Assets::set_metadata(
				RuntimeOrigin::signed(ALICE),
				USDX_ASSET_ID,
				b"USDX".to_vec(),
				b"USDX".to_vec(),
				4
			));

			assert_ok!(Psm::mint(
				RuntimeOrigin::signed(BOB),
				INTERNAL_ASSET_ID,
				USDX_ASSET_ID,
				10_000 * USDX_UNIT,
				Permill::zero()
			));
			assert_eq!(
				PsmDebt::<Test>::get(INTERNAL_ASSET_ID, USDX_ASSET_ID),
				10_000 * INTERNAL_UNIT
			);
		});
```

**File:** substrate/frame/psm/src/tests.rs (L3057-3082)
```rust
	#[test]
	fn mint_uses_snapshot_when_internal_decimals_drift() {
		new_test_ext().execute_with(|| {
			set_zero_fees(USDC_ASSET_ID);
			// internal starts at 6 decimals; InternalDecimals snapshot matches. The owner
			// (ALICE) changes the internal asset's live metadata to simulate drift.
			assert_ok!(Assets::set_metadata(
				RuntimeOrigin::signed(ALICE),
				INTERNAL_ASSET_ID,
				b"INTERNAL".to_vec(),
				b"INTERNAL".to_vec(),
				8
			));

			assert_ok!(Psm::mint(
				RuntimeOrigin::signed(ALICE),
				INTERNAL_ASSET_ID,
				USDC_ASSET_ID,
				1000 * INTERNAL_UNIT,
				Permill::zero()
			));
			assert_eq!(
				PsmDebt::<Test>::get(INTERNAL_ASSET_ID, USDC_ASSET_ID),
				1000 * INTERNAL_UNIT
			);
		});
```

**File:** prdoc/stable2606/pr_11819.prdoc (L1-23)
```text
title: 'pallet-psm: support external assets with different decimal precision'
doc:
- audience: Runtime Dev
  description: |-
    Previously pallet-psm rejected any external stablecoin whose decimals did
    not match pUSD. This change normalizes to pUSD units internally so the PSM
    can approve assets with arbitrary decimal precision within a safe range.

    Core changes:
    - New storage: per-asset `AssetDecimals` snapshot and pallet-wide
      `StableDecimals` snapshot. Storage version bumped to 2.
    - Conversion helpers `external_to_pusd` / `pusd_to_external` with checked
      arithmetic and `MAX_DECIMALS_DIFF = 24` to prevent overflow.
    - `mint` and `redeem` use round-trip rounding. Truncation dust stays in the
      caller's wallet on both paths (symmetric behavior), no value is trapped
      in the reserve and no hidden dust is routed to the fee destination.
    - `PsmDebt` now denominates in pUSD units so aggregate ceilings and issuance
      checks are meaningful across mixed-decimal assets.
    - Runtime drift guard: `mint`/`redeem` return `DecimalsMismatch` if live
      metadata diverges from the registration snapshot; that asset halts until
      governance intervenes.
    - New errors: `DecimalsRangeExceeded`, `ConversionOverflow`,
      `AmountTooSmallAfterConversion`.
```

**File:** prdoc/stable2606-2/pr_13062.prdoc (L1-8)
```text
title: 'pallet-psm: use recorded decimals when minting'
doc:
- audience: Runtime Dev
  description: |-
    Keeps PSM mint conversions and external-asset registration tied to the decimal
    snapshots captured when the PSM and external asset are registered, matching redemption
    behavior. Changes to live asset metadata no longer stop minting or alter the debt
    conversion rate.
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L695-706)
```rust
	/// Execute the decimals call.
	fn decimals(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		env.charge(<Runtime as Config<Instance>>::WeightInfo::get_metadata())?;

		let metadata = pallet_assets::Pallet::<Runtime, Instance>::get_metadata(asset_id)
			.ok_or(Error::Revert(Revert { reason: "Metadata not found".into() }))?;

		Ok(IERC20::decimalsCall::abi_encode_returns(&metadata.decimals))
	}
```

**File:** substrate/frame/support/src/traits/tokens/fungible/metadata.rs (L26-34)
```rust
/// Trait for inspecting fungible token metadata.
pub trait Inspect<AccountId>: super::Inspect<AccountId> {
	/// Returns the name of the token.
	fn name() -> Vec<u8>;
	/// Returns the ticker symbol of the token.
	fn symbol() -> Vec<u8>;
	/// Returns the number of decimals this asset uses to represent one unit.
	fn decimals() -> u8;
}
```
