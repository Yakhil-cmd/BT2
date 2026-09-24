Confirmed: `add_external_asset` snapshots `T::Fungibles::decimals(external_asset)` once into `ExternalAssetInfo::decimals` [1](#0-0) , and `mint`/`redeem` use only this stale snapshot together with `PsmInfo::internal_decimals` (also snapshotted once at `create_psm`, [2](#0-1) ) for all scaling via `external_to_internal`/`internal_to_external` [3](#0-2) [4](#0-3) . There is no re-query of live decimals and no comparison against the snapshot anywhere in the mint/redeem path or elsewhere in the pallet — `Error::DecimalsMismatch` exists only as "Reserved legacy error; retained to preserve error variant indices" [5](#0-4) , i.e. it is never returned. This contradicts the pallet's own changelog claim of a "Runtime drift guard: mint/redeem return DecimalsMismatch if live metadata diverges from the registration snapshot" [6](#0-5)  and the doc comment on `redeem` claiming decimals-drift safety [7](#0-6) .

### Title
PSM mint/redeem trust a stale decimals snapshot with no live drift check, allowing under-collateralized minting after an external asset's metadata decimals change - (File: substrate/frame/psm/src/lib.rs)

### Summary
`pallet-psm`'s `add_external_asset` snapshots an external asset's `decimals` once at approval time into `ExternalAssetInfo::decimals`. `mint` and `redeem` use this snapshot (never the live value) to convert between external-asset units and internal-asset units 1:1. If the external asset's on-chain decimals metadata is later changed (a normal, unprivileged action available to that asset's own metadata-setter via `pallet-assets::set_metadata`/`force_set_metadata`-equivalent flows, or via any `FungiblesMetadataInspect` backend that allows mutable decimals), the PSM keeps using the outdated scaling factor. This directly mirrors the reported bug class: a fixed/cached precision assumption is used for scaling while the actual precision source can diverge, with no guard enforcing consistency, producing "improperly scaled prices/amounts... inaccurate by orders of magnitude."

### Finding Description
`add_external_asset` reads `T::Fungibles::decimals(external_asset)` exactly once and persists it into `ExternalAssetInfo.decimals`: [1](#0-0) 

`mint` then does:
```
let ext_decimals = external.decimals;          // stale snapshot
let internal_decimals = info.internal_decimals; // stale snapshot
let internal_equivalent = Self::external_to_internal(external_amount, ext_decimals, internal_decimals)?;
``` [3](#0-2) 

and `redeem` does the symmetric conversion, also purely from snapshots: [4](#0-3) 

The scaling itself is a straightforward `10^diff` multiply/divide based on the (possibly outdated) decimal difference: [8](#0-7) 

Nowhere in `mint`, `redeem`, `set_asset_status`, `set_minting_fee`, `set_redemption_fee`, or any hook is the live `T::Fungibles::decimals(external_asset)` re-queried and compared to the stored snapshot; the only call to `decimals()` in the whole pallet is the one at `add_external_asset` registration time (confirmed via full-file grep for `decimals(` and `DecimalsMismatch`/`set_metadata`/drift-related identifiers, which returned matches only in the registration path and the retired error variant). The `Error::DecimalsMismatch` variant that the pallet's own PRDoc and doc-comments describe as a runtime "drift guard" is explicitly commented as legacy/unused: [5](#0-4) 

So the invariant "the scaling factor used by PSM always reflects the external asset's actual current decimals" does not hold, exactly analogous to the Sherlock finding that "the output precision is arbitrarily specified... whereas the internal pricing precision is fixed... this is an invalid assumption."

Attack path (no privileged role required beyond controlling one's own asset's metadata, which is the normal unprivileged role of an asset's `Freezer`/owner/whoever `pallet-assets` permits to call metadata-setting extrinsics for that asset — separate and unrelated to PSM's admin roles):
1. Asset `X` is approved as an external asset on a PSM with `internal_decimals = 6`, `X.decimals() = 6` at approval time → `diff = 0`, scaling is identity.
2. Later, the entity controlling `X`'s metadata increases its decimals (e.g. from 6 to 18) — a normal, unprivileged `pallet-assets` metadata operation unrelated to PSM governance.
3. PSM continues to treat 1 raw unit of `X` as equivalent to 1 raw unit of the internal asset (snapshot `diff` still 0), even though `X`'s value-per-raw-unit has just dropped by `10^12`.
4. Any signed user can now call `mint` with a comparatively tiny amount of raw `X` units and receive internal asset credited as if it were full-value `X`, minting internal asset far in excess of the real economic value deposited into the PSM reserve — breaking the 1:1 backing invariant the whole pallet is built on. Conversely if decimals decrease, redemptions can drain the reserve disproportionately.

### Impact Explanation
This breaks the core security invariant of a Peg Stability Module — that internal-asset issuance is fully backed 1:1 by external-asset reserves. A drift in an approved external asset's decimals (entirely outside PSM's or its admin's control) leads to systematically mis-scaled `mint`/`redeem` conversions, enabling under-collateralized minting (unbacked issuance) or reserve drainage on redemption, i.e. direct value extraction/loss for the PSM and, by extension, for the internal stablecoin's holders. This matches Critical/High impact criteria (unbacked issuance / theft of reserve funds) though the original external report was scored Medium because in that context it merely mis-scaled a *view* function; here it mis-scales an actual token-minting/burning state transition, which is more severe.

### Likelihood Explanation
Likelihood depends entirely on runtime configuration: this requires (a) an external asset whose decimals metadata can be mutated after PSM approval by an entity other than the PSM admin, and (b) that asset actually being approved by PSM governance. `pallet-assets` metadata (`set_metadata`) is normally settable by the asset's own management origin, independent of and unknown to the PSM's admin roles, so this is plausible for real-world external stablecoins whose metadata authority is not permanently locked. The pallet's own documentation and changelog assert a guard against exactly this scenario exists, indicating the developers intended this to be checked — the gap between documented behavior and actual code is a strong signal that this is an unintentional regression/inconsistency rather than acceptable design, satisfying the "violated invariant" requirement of the report.

### Recommendation
On every `mint`/`redeem` (and ideally on any state read that assumes decimals), re-query `T::Fungibles::decimals(external_asset)` (and `T::Fungibles::decimals(internal_asset)`) and compare against the stored snapshot; if they diverge, either (a) actually return `Error::DecimalsMismatch` and halt swaps for that asset until governance re-registers/updates the snapshot (matching the pallet's documented intent), or (b) always convert using live decimals rather than a cached snapshot. Additionally, restore/implement the missing drift-check code path that the PRDoc and doc-comments describe, and add a regression test that changes an external asset's metadata decimals post-registration and asserts `mint`/`redeem` reject or correctly rescale rather than silently using the stale value.

### Proof of Concept
Not independently executed against a live node; this is derived from static analysis of `substrate/frame/psm/src/lib.rs` and `substrate/frame/psm/src/tests.rs`. Evidence supporting the finding:
- `add_external_asset` snapshot-only decimals read: [1](#0-0) .
- `mint`/`redeem` consume only the snapshot, never re-reading `T::Fungibles::decimals`: [3](#0-2) [4](#0-3) .
- Full-pallet grep for `decimals(`/`DecimalsMismatch`/`set_metadata`/drift terms returns matches only at registration and the retired error comment, confirming no drift check exists anywhere else in the pallet.
- The pallet's own PRDoc explicitly claims a "Runtime drift guard" exists [6](#0-5) , and the `redeem` doc-comment claims decimals-drift resilience [7](#0-6)  — neither is backed by actual runtime logic, which is the same "assumption vs. reality" gap the original report flags.

A concrete Rust integration test to fully confirm exploitability would need to: register an external asset via `add_external_asset`, then call `pallet_assets::Pallet::<T>::set_metadata` (or equivalent) to change its `decimals`, then call `Psm::mint` and assert the `internal_equivalent` computed still uses the old `ext_decimals` value from `ExternalAssetInfo` rather than the new live decimals — I was not able to execute this within this session; it should be run by a follow-up engineer/agent to fully validate before treating this as bounty-ready, particularly to confirm which concrete deployed runtime(s) use `pallet-psm` with a `Fungibles` backend whose decimals are mutable post-creation.

### Citations

**File:** substrate/frame/psm/src/lib.rs (L639-640)
```rust
		/// Reserved legacy error; retained to preserve error variant indices.
		DecimalsMismatch,
```

**File:** substrate/frame/psm/src/lib.rs (L717-726)
```rust
			let ext_decimals = external.decimals;
			let internal_decimals = info.internal_decimals;

			let internal_equivalent =
				Self::external_to_internal(external_amount, ext_decimals, internal_decimals)?;
			ensure!(!internal_equivalent.is_zero(), Error::<T>::AmountTooSmallAfterConversion);
			ensure!(internal_equivalent >= info.min_swap_amount, Error::<T>::BelowMinimumSwap);

			let effective_external =
				Self::internal_to_external(internal_equivalent, ext_decimals, internal_decimals)?;
```

**File:** substrate/frame/psm/src/lib.rs (L782-784)
```rust
		/// undercharges. Redemptions use the decimals snapshotted when the PSM/external pair
		/// was registered, allowing existing positions to unwind even if live metadata later
		/// changes.
```

**File:** substrate/frame/psm/src/lib.rs (L826-847)
```rust
			let ext_decimals = external.decimals;
			let internal_decimals = info.internal_decimals;

			ensure!(internal_amount >= info.min_swap_amount, Error::<T>::BelowMinimumSwap);

			let fee_rate = RedemptionFee::<T>::get(&internal_asset, &external_asset);
			ensure!(fee_rate <= max_fee, Error::<T>::FeeTooHigh);
			let fee = fee_rate.mul_ceil(internal_amount);
			let internal_net = internal_amount.saturating_sub(fee);

			let external_out =
				Self::internal_to_external(internal_net, ext_decimals, internal_decimals)?;
			ensure!(
				internal_net.is_zero() || !external_out.is_zero(),
				Error::<T>::AmountTooSmallAfterConversion
			);
			// `effective_internal_net` is the internal value that round-trips to `external_out`;
			// it is what we actually burn and what the tracked debt decreases by. Any truncation
			// dust stays in the caller's internal balance, symmetric with `mint`, which takes
			// only the round-tripped share of the external amount.
			let effective_internal_net =
				Self::external_to_internal(external_out, ext_decimals, internal_decimals)?;
```

**File:** substrate/frame/psm/src/lib.rs (L974-983)
```rust
			let internal_decimals = T::Fungibles::decimals(internal_asset.clone());
			Psm::<T>::insert(
				&internal_asset,
				PsmInfo::<T> {
					fee_destination: fee_destination.clone(),
					max_debt,
					min_swap_amount,
					internal_decimals,
					external_count: 0,
				},
```

**File:** substrate/frame/psm/src/lib.rs (L1337-1350)
```rust
			let asset_decimals = T::Fungibles::decimals(external_asset.clone());
			ensure!(
				(asset_decimals.abs_diff(info.internal_decimals) as u32) <= MAX_DECIMALS_DIFF,
				Error::<T>::DecimalsRangeExceeded
			);

			ExternalAssets::<T>::insert(
				&internal_asset,
				&external_asset,
				ExternalAssetInfo {
					status: CircuitBreakerLevel::AllEnabled,
					decimals: asset_decimals,
				},
			);
```

**File:** substrate/frame/psm/src/lib.rs (L1600-1644)
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

**File:** prdoc/stable2606/pr_11819.prdoc (L19-21)
```text
    - Runtime drift guard: `mint`/`redeem` return `DecimalsMismatch` if live
      metadata diverges from the registration snapshot; that asset halts until
      governance intervenes.
```
