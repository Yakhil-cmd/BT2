### Title
`SetAppendix` refund guard installed too late in `remote_transfer_xcm`, causing the withdrawn remote fee to be trapped (not the treasury's spend amount) - ([File: system-parachains/encointer/src/treasuries_xcm_payout.rs])

### Summary
`remote_transfer_xcm` builds `WithdrawAsset(remote_fee) -> PayFees{remote_fee} -> SetAppendix(RefundSurplus, DepositAsset) -> TransferAsset`. Because `SetAppendix` is installed only after `WithdrawAsset`/`PayFees` execute, any failure of those two earlier instructions (e.g. the hardcoded `ConstantKsmFee::REMOTE_XCM_TRANSFER_REMOTE_EXECUTION_FEE` no longer covering AssetHub's actual weight-to-fee) leaves the withdrawn fee asset in the holding register with no appendix set, so it is dropped as `AssetTrap` instead of being refunded to the treasury's remote account.

### Finding Description
`remote_transfer_xcm` (system-parachains/encointer/src/treasuries_xcm_payout.rs:254-281) constructs: [1](#0-0) 

The program order is `DescendOrigin -> WithdrawAsset(remote_fee) -> PayFees{remote_fee} -> SetAppendix(RefundSurplus, DepositAsset{beneficiary: from_at_target}) -> TransferAsset`. The comment on the `from_at_target` variable states "We need this one for the refunds," confirming that the intent of `SetAppendix` is to guarantee any leftover/failed fee asset is returned to the treasury's sovereign account on the remote chain [2](#0-1) .

However, in XCM's instruction model, `SetAppendix` only takes effect for the remainder of the *current* program execution starting at the point it is executed; it does not retroactively protect instructions that ran (and possibly failed) before it. If `WithdrawAsset(remote_fee)` succeeds but `PayFees{remote_fee}` fails (e.g. `remote_fee` is insufficient to buy the required weight because AssetHub's `WeightToFee` conversion changed relative to the hardcoded constant `REMOTE_XCM_TRANSFER_REMOTE_EXECUTION_FEE = 1_942_312_457`), execution halts at instruction #3, before `SetAppendix` (#4) is ever reached. No appendix is installed, so the withdrawn `remote_fee` asset sitting in the holding register at the point of failure is not refunded — it is trapped and an `AssetTrap` event is emitted on the remote chain (AssetHub), with the asset only recoverable via a manual/governance `claim_assets` on that chain, not automatically returned to the Encointer treasury.

Note on scope of the actual "spend" amount: `TransferAsset { beneficiary, assets: (asset_id, amount) }` is the final instruction (#5) and is never reached if `PayFees` fails. `TransferAsset` performs a direct balance transfer from the current origin's local balance to the beneficiary; it does not route the spend amount through the holding register. Therefore the main payout amount (the community's/treasury's spend) is never withdrawn or moved at all when this failure occurs — it remains untouched in the treasury's account on AssetHub. Only the fixed, comparatively small `remote_fee` (the `PayFees`-designated withdrawal) is exposed to the trap.

Reachability/attacker path: `pallet_encointer_treasuries::swap_native` / `swap_asset` extrinsics (both weighed as `WeightInfo::swap_native`/`swap_asset`) are user-facing calls that ultimately invoke `Transfer::transfer` → `TransferOverXcm::transfer` → `get_remote_transfer_xcm` → `remote_transfer_xcm`, and are dispatched from a signed origin [3](#0-2) [4](#0-3) . `TransferOverXcm` is wired as the `Paymaster` for `pallet_encointer_treasuries::Config` [5](#0-4) , meaning an ordinary user calling `swap_native`/`swap_asset` triggers this exact XCM program with themselves able to indirectly control the trigger timing (e.g. by observing AssetHub fee-market conditions and calling when they are unfavorable). The constant `ConstantKsmFee::REMOTE_XCM_TRANSFER_REMOTE_EXECUTION_FEE` is fixed at compile time and is only validated against a snapshot of AssetHub's `WeightToFee`, so real-world fee-market drift (e.g. block congestion, `SlowAdjustingFeeUpdate`) can make it insufficient over time without a code/parameter update [6](#0-5) .

### Impact Explanation
The concrete, scoped impact is a repeatable loss of the fixed `REMOTE_XCM_TRANSFER_REMOTE_EXECUTION_FEE` (~1_942_312_457 KSM planck ≈ 0.00194 KSM) per failed swap whenever `PayFees` fails on AssetHub before `SetAppendix` is installed — this fee asset is trapped rather than refunded to the treasury. This is *not* the "permanent drain of the full treasury spend amount" implied by the question: `TransferAsset` (which moves the actual spend/payout amount) never executes in this failure branch, so the treasury's principal funds for that specific swap remain intact and un-lost — they are simply not paid out (the swap effectively fails, and depending on the local side of `swap_native`/`swap_asset`, the user's already-burned community tokens or locally-reserved funds may also need reconciliation, but that is a separate local-side accounting question not covered by this XCM snippet). The real, bounded impact is: each triggerable `PayFees` failure permanently burns the fixed remote-fee KSM amount from the treasury's AssetHub sovereign balance with no refund path, and this is repeatable for as long as the fee-market condition (AssetHub fee > hardcoded constant) holds.

### Likelihood Explanation
Preconditions: (1) an unprivileged user must be able to call `swap_native`/`swap_asset` (ordinary signed-origin extrinsics), and (2) AssetHub's fee-market conditions at execution time must cause the constant fee to under-cover the `PayFees` weight requirement (e.g. congestion, fee-multiplier drift, or future runtime upgrades on AssetHub that raise weight costs). Precondition (2) is plausible over time given `SlowAdjustingFeeUpdate`-style dynamic fee mechanisms on AssetHub, and is externally observable, letting an attacker time calls to coincide with unfavorable fee conditions. The attacker does not need to "drive up" fees maliciously in a targeted way for this specific message — natural fee-market variance is sufficient, making this a real, moderately likely, repeatable griefing/fee-loss condition rather than a one-off edge case.

### Recommendation
Move `SetAppendix(RefundSurplus, DepositAsset)` to be the *first* instruction in the program (before `WithdrawAsset`/`PayFees`), so that any failure at any subsequent step — including the withdraw/pay-fees step — is covered by the refund appendix and any assets left in holding at time of failure are returned to `from_at_target` instead of being trapped. Additionally, consider deriving the remote fee dynamically (e.g. via `report_holding`/weight queries or periodic recalibration) instead of relying solely on a hardcoded constant, to reduce the frequency of `PayFees` failures.

### Proof of Concept
xcm-emulator test plan (extends the existing `remote_treasury_native_payout_works` test in `integration-tests/emulated/tests/encointer/encointer-kusama/src/tests/remote_treasury_payout.rs`):
1. On `AssetHubKusama`, artificially bump the runtime's `WeightToFee` multiplier (or use `pallet_transaction_payment`'s fee multiplier storage if exposed for test manipulation) so that the weight cost of the generated remote XCM program exceeds `ConstantKsmFee::REMOTE_XCM_TRANSFER_REMOTE_EXECUTION_FEE`.
2. Fund the Encointer treasury's AssetHub sovereign account with KSM only enough to cover the *old* fee, or leave the fee amount fixed while raising the required weight-fee so `PayFees` errors with `FeesNotMet`/`TooExpensive`.
3. From `EncointerKusama`, dispatch `pallet_encointer_treasuries::swap_native` (or call `EncointerTreasuries::do_spend_asset`/`Transfer::transfer` directly as in the existing tests) to trigger `TransferOverXcm::transfer`.
4. On `AssetHubKusama::execute_with`, assert:
   - `RuntimeEvent::PolkadotXcm(pallet_xcm::Event::AssetsTrapped { .. })` (or the lower-level `xcm_executor` `AssetTrap` outcome) fires for the `remote_fee` asset.
   - No `DepositAsset` back to `from_at_target` (i.e., the treasury's sovereign account balance does **not** recover the withdrawn fee).
   - The treasury's AssetHub sovereign account balance decreases by exactly `remote_fee()` with no corresponding refund event.
   - The intended spend amount (`SPEND_AMOUNT`) is *not* transferred to the recipient and remains in the treasury's account, confirming the bug is scoped to the fee asset only, not the principal.

### Citations

**File:** system-parachains/encointer/src/treasuries_xcm_payout.rs (L30-45)
```rust
// This is the value that has been queried from the Asset Hub Kusama runtime.
// There is an integration test in `integration-tests/emulated/tests/encointer/encointer-kusama/
// That verifies that this fee is correct and will catch fee changes in Asset-Hub Kusama
pub const REMOTE_XCM_TRANSFER_REMOTE_EXECUTION_FEE: u128 = 1942312457;

pub trait GetRemoteFee {
	fn get_remote_fee(xcm: Xcm<()>, asset_id: Option<AssetId>) -> Asset;
}

pub struct ConstantKsmFee;

impl GetRemoteFee for ConstantKsmFee {
	fn get_remote_fee(_xcm: Xcm<()>, _asset_id: Option<AssetId>) -> Asset {
		fee_asset(REMOTE_XCM_TRANSFER_REMOTE_EXECUTION_FEE)
	}
}
```

**File:** system-parachains/encointer/src/treasuries_xcm_payout.rs (L108-121)
```rust
	fn transfer(
		from: &Self::Payer,
		to: &Self::Beneficiary,
		asset_kind: Self::AssetKind,
		amount: Self::Balance,
	) -> Result<Self::Id, Self::Error> {
		let (message, asset_location, query_id) =
			Self::get_remote_transfer_xcm(from, to, asset_kind, amount)?;

		let (ticket, _delivery_fees) =
			Router::validate(&mut Some(asset_location), &mut Some(message))?;
		Router::deliver(ticket)?;
		Ok(query_id)
	}
```

**File:** system-parachains/encointer/src/treasuries_xcm_payout.rs (L263-266)
```rust
	// Transform `from` into Location::new(1, XX([Parachain(source), from.interior }])
	// We need this one for the refunds.
	let from_at_target = append_from_to_target(from_location.clone(), destination.clone())?;

```

**File:** system-parachains/encointer/src/treasuries_xcm_payout.rs (L267-278)
```rust
	let xcm = Xcm(vec![
		// Transform origin into Location::new(1, X2([Parachain(SourceParaId), from.interior }])
		DescendOrigin(from_location.interior.clone()),
		// For simplicity, we assume now that the treasury has KSM and pays fees with KSM.
		WithdrawAsset(vec![remote_fee.clone()].into()),
		PayFees { asset: remote_fee },
		SetAppendix(Xcm(vec![
			RefundSurplus,
			DepositAsset { assets: AssetFilter::Wild(WildAsset::All), beneficiary: from_at_target },
		])),
		TransferAsset { beneficiary, assets: (asset_id, amount).into() },
	]);
```

**File:** system-parachains/encointer/src/weights/pallet_encointer_treasuries.rs (L53-71)
```rust
impl<T: frame_system::Config> pallet_encointer_treasuries::WeightInfo for WeightInfo<T> {
	/// Storage: `EncointerTreasuries::SwapNativeOptions` (r:1 w:1)
	/// Proof: `EncointerTreasuries::SwapNativeOptions` (`max_values`: None, `max_size`: Some(134), added: 2609, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:2 w:2)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `EncointerBalances::Balance` (r:2 w:2)
	/// Proof: `EncointerBalances::Balance` (`max_values`: None, `max_size`: Some(93), added: 2568, mode: `MaxEncodedLen`)
	/// Storage: `EncointerBalances::DemurragePerBlock` (r:1 w:0)
	/// Proof: `EncointerBalances::DemurragePerBlock` (`max_values`: None, `max_size`: Some(41), added: 2516, mode: `MaxEncodedLen`)
	fn swap_native() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `733`
		//  Estimated: `6196`
		// Minimum execution time: 71_533_000 picoseconds.
		Weight::from_parts(74_113_000, 0)
			.saturating_add(Weight::from_parts(0, 6196))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(5))
	}
```

**File:** system-parachains/encointer/src/lib.rs (L617-635)
```rust
pub type TransferOverXcm = crate::treasuries_xcm_payout::TransferOverXcm<
	crate::xcm_config::XcmRouter,
	crate::PolkadotXcm,
	ConstU32<{ 6 * HOURS }>,
	AccountId,
	VersionedLocatableAsset, // Use this as AssetKind in encointer_treasuries::Config too!
	LocatableAssetConverter,
	AliasesIntoAccountId32<AnyNetwork, AccountId>,
	ConstantKsmFee,
>;

impl pallet_encointer_treasuries::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = pallet_balances::Pallet<Runtime>;
	type PalletId = TreasuriesPalletId;
	type WeightInfo = weights::pallet_encointer_treasuries::WeightInfo<Runtime>;
	type AssetKind = VersionedLocatableAsset;
	#[cfg(not(feature = "runtime-benchmarks"))]
	type Paymaster = TransferOverXcm;
```
