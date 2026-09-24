### Title
Peg Stability Module performs fixed 1:1 swaps with no price-deviation check, enabling depeg arbitrage and bad-debt accrual - (File: substrate/frame/psm/src/lib.rs)

### Summary
`pallet-psm` implements a Peg Stability Module (PSM) that swaps an "internal" stablecoin against approved "external" stablecoins (e.g. USDC, USDT) at a hardcoded 1:1 ratio, adjusted only for token decimals — never for actual market price. This is structurally the same flaw as the Hubble Exchange oracle issue: a stablecoin's value is assumed to be permanently pegged to $1 with no live price feed, so if the external asset depegs, `mint`/`redeem` still execute at par, letting an attacker extract value from the reserve and leaving the internal asset under-collateralized.

### Finding Description
The pallet's public entry points `mint` and `redeem` are permissionless signed extrinsics reachable by any account holding the approved external asset: [1](#0-0) 

Conversion between external and internal amounts is done purely through `external_to_internal`/`internal_to_external`, which — per the module documentation — only scale by the snapshotted decimals of each asset (`internal_decimals`, `ExternalAssetInfo::decimals`), bounded by `MAX_DECIMALS_DIFF`: [2](#0-1) [3](#0-2) 

Nowhere in `Config` is there any price-oracle dependency (`type Fungibles`, `type Consideration`, `type CreateOrigin`, `type PalletId`, `type MaxExternals` are the only external inputs): [4](#0-3) 

The module doc explicitly states the design assumes 1:1 backing ("PSM Debt: Total internal asset minted through a PSM, backed 1:1 by external assets in that PSM's reserve"): [5](#0-4) 

`mint` transfers `external_amount` in at full nominal (decimal-adjusted) value and mints internal asset 1:1 minus a governance-configured fee (default 0.5%, `MintingFee`/`DefaultFee`): [6](#0-5) [7](#0-6) 

`redeem` burns internal asset and pays out external at the same fixed 1:1 rate: [8](#0-7) 

The only defense mechanism is `CircuitBreakerLevel`, a reactive, admin-triggered switch (not tied to any live price feed): [9](#0-8) 

This mirrors the Hubble `Oracle.sol` bug exactly: the "price" of the stable asset is hardcoded (here, implicitly 1:1 via decimal scaling instead of an actual oracle read), and there is no on-chain mechanism to detect or react to the external asset's real market price diverging from $1. An attacker needs no privileged role — only ownership of the (possibly depegged) external asset and a signed account.

### Impact Explanation
If an approved external asset depegs below $1 (a realistic, historically observed event for USDC, USDT, DAI, etc.):
1. An attacker acquires the depegged external asset cheaply on the open market (e.g., $0.90 per unit).
2. The attacker calls `mint` on the PSM, depositing the depegged asset and receiving internal stablecoin at full par value (minus the ~0.5% fee), immediately realizing an arbitrage profit and depleting the PSM's real economic reserve value relative to its outstanding `PsmDebt`.
3. Because `PsmDebt` still records the internal-asset debt as fully 1:1 backed, the internal stablecoin becomes under-collateralized — subsequent `redeem` calls by other honest holders will be paid from a reserve that is worth less than the recorded debt, producing bad debt / potential insolvency for the internal asset, exactly the "significant bad debt" scenario in the referenced report.
4. Because the same fixed-rate mechanism runs in both directions, a permanent depeg leaves the PSM systematically mispriced with no automated correction, only a manual (governance/emergency-admin) circuit breaker that acts after the fact.

This is an unbacked-issuance / insolvency-class problem (internal stablecoin minted against devalued collateral) affecting any runtime that deploys `pallet-psm`, which is production code shipped as part of Polkadot Stablecoin on AssetHub tooling (see `prdoc/stable2512/pr_9815.prdoc` context for the oracle work in the same initiative).

### Likelihood Explanation
Likelihood depends entirely on runtime configuration: this is a structural, protocol-design issue inherent to any PSM instance that approves an external asset without pairing it with independent price validation before allowing `mint`. Since `mint`/`redeem` are unauthenticated (any signed account), and external-asset acquisition requires no privileged access, the only precondition is a genuine depeg event of an approved external asset — a market condition outside the PSM's control and historically observed multiple times for major stablecoins. The pallet documentation itself frames the design as relying on a hard 1:1 assumption, so this is not a bug in the implementation of the intended design but a missing safeguard against the design's own known weak point (same characterization Sherlock gave the Hubble report: "This will protect accounts... particularly if the depeg is permanent").

### Recommendation
- Integrate a price-deviation check (e.g., via `pallet-oracle` or an external price feed trait) before allowing `mint`, rejecting or throttling minting when the external asset's live price deviates materially from $1.
- Consider making the circuit breaker reactive to an oracle price feed automatically (not solely admin-triggered), so `CircuitBreakerLevel::MintingDisabled` can be set programmatically on detected depegs.
- Track and expose the mark-to-market backing ratio (`reserve value / PsmDebt`) so redemptions can be pro-rated or halted rather than paying out full par value from a reserve backed by devalued collateral.
- Document clearly that runtimes must not approve an external asset on a PSM instance without a live price-monitoring integration, since the current 1:1 decimal-only conversion offers no depeg protection.

### Proof of Concept
No PoC was executed. Based on static analysis of `mint`/`redeem` and the absence of any oracle/price-feed type in `Config`, the reproduction path would be:
1. Using the existing `substrate/frame/psm/src/mock.rs` / `tests.rs` harness, register a PSM instance with an external asset (`create_psm`, `add_external_asset`).
2. Simulate a depeg by minting the external asset to a test account with `Assets::mint_into` at zero "real" cost (in the mock this is trivial since there's no external DEX price reference — this itself demonstrates the missing check, since the pallet cannot distinguish a legitimately-acquired external token from one worth less on the open market).
3. Call `Psm::mint` with that external asset amount and observe `internal_received` computed strictly via decimal scaling (`external_to_internal`), confirming no price-deviation guard exists to reduce output or reject the swap.
4. Call `Psm::redeem` from another account and confirm the reserve (`get_reserve`) can be drawn down to below the value implied by outstanding `PsmDebt` once assumption (1) breaks in the real world — this step cannot be demonstrated purely on-chain since price deviation is an off-chain/market fact the pallet has no way to observe, which is precisely the vulnerability.

This is reported as an architectural/Medium-High finding (design gap, not a coding defect) analogous to the Hubble `Oracle.sol` manual-stable-price issue; exact severity depends on how any given runtime configures/monitors its PSM instances, since `pallet-psm` itself provides no built-in oracle integration point.

### Citations

**File:** substrate/frame/psm/src/lib.rs (L42-61)
```rust
//! ## Overview
//!
//! A PSM strengthens its internal asset's peg by providing arbitrage opportunities:
//! - When the internal asset trades **above** $1: Users swap external assets for the internal asset
//!   and sell for profit.
//! - When the internal asset trades **below** $1: Users buy cheap internal asset and swap for
//!   external assets.
//!
//! This creates a price corridor bounded by the minting and redemption fees.
//!
//! ### Key Concepts
//!
//! * **PSM instance**: A configured Peg Stability Module, keyed by its internal asset id and
//!   described by [`PsmInfo`]. Each instance has its own reserve account derived from
//!   `blake2_256((PalletId::TYPE_ID, PalletId, internal_asset).encode())`.
//! * **Minting**: Deposit external asset → receive internal asset (minus fee).
//! * **Redemption**: Burn internal asset → receive external asset (minus fee).
//! * **Reserve**: External asset balance held by a PSM's reserve account (derived, not stored).
//! * **PSM Debt**: Total internal asset minted through a PSM, backed 1:1 by external assets in that
//!   PSM's reserve.
```

**File:** substrate/frame/psm/src/lib.rs (L153-187)
```rust
	/// Circuit breaker levels for emergency control.
	#[derive(
		Encode,
		Decode,
		DecodeWithMemTracking,
		MaxEncodedLen,
		TypeInfo,
		Clone,
		Copy,
		PartialEq,
		Eq,
		Debug,
		Default,
	)]
	pub enum CircuitBreakerLevel {
		/// Normal operation, all swaps enabled.
		#[default]
		AllEnabled,
		/// Minting disabled, redemptions still allowed.
		MintingDisabled,
		/// All swaps disabled.
		AllDisabled,
	}

	impl CircuitBreakerLevel {
		/// Whether this level allows minting (external → internal).
		pub const fn allows_minting(&self) -> bool {
			matches!(self, CircuitBreakerLevel::AllEnabled)
		}

		/// Whether this level allows redemption (internal → external).
		pub const fn allows_redemption(&self) -> bool {
			!matches!(self, CircuitBreakerLevel::AllDisabled)
		}
	}
```

**File:** substrate/frame/psm/src/lib.rs (L262-268)
```rust
	/// Suggested fee of 0.5% for minting and redemption.
	pub(crate) struct DefaultFee;
	impl Get<Permill> for DefaultFee {
		fn get() -> Permill {
			Permill::from_parts(5_000)
		}
	}
```

**File:** substrate/frame/psm/src/lib.rs (L270-292)
```rust
	/// Maximum absolute difference between an external asset's decimals and the internal
	/// asset's decimals. Bounds the scaling factor `10^diff` well below `u128::MAX`
	/// so realistic balances cannot overflow during conversion.
	pub const MAX_DECIMALS_DIFF: u32 = 24;

	/// On-chain record of a PSM instance.
	#[derive(
		Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Clone, PartialEq, Eq, Debug,
	)]
	#[scale_info(skip_type_params(T))]
	pub struct PsmInfo<T: Config> {
		/// Account receiving minting and redemption fees, denominated in the internal asset.
		pub fee_destination: T::AccountId,
		/// This PSM instance's debt ceiling, in internal-asset units.
		pub max_debt: BalanceOf<T>,
		/// Minimum swap amount for this instance, in internal-asset units. Swaps whose
		/// internal-equivalent falls below this are rejected with [`Error::BelowMinimumSwap`].
		pub min_swap_amount: BalanceOf<T>,
		/// Snapshot of the internal asset's decimals at install time.
		pub internal_decimals: u8,
		/// Number of approved external assets attached to this instance.
		pub external_count: u32,
	}
```

**File:** substrate/frame/psm/src/lib.rs (L312-330)
```rust
	/// On-chain record of an external asset approved on a PSM instance.
	#[derive(
		Encode,
		Decode,
		DecodeWithMemTracking,
		MaxEncodedLen,
		TypeInfo,
		Clone,
		Copy,
		PartialEq,
		Eq,
		Debug,
	)]
	pub struct ExternalAssetInfo {
		/// Per-external circuit breaker status.
		pub status: CircuitBreakerLevel,
		/// Snapshot of the external asset's decimals at registration time.
		pub decimals: u8,
	}
```

**File:** substrate/frame/psm/src/lib.rs (L332-382)
```rust
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Fungibles implementation for both internal and external assets.
		type Fungibles: FungiblesMutate<Self::AccountId, AssetId = Self::AssetId>
			+ FungiblesMetadataInspect<Self::AccountId>
			+ FungiblesRolesInspect<Self::AccountId>;

		/// Consideration for PSM creation. Runtimes can price this from the PSM footprint or
		/// anything else they choose.
		type Consideration: Consideration<Self::AccountId, Footprint>;

		/// Origin permitted to create a PSM for a given internal asset; succeeds with the
		/// optional account that pays the creation consideration. Returning `None` creates without
		/// a deposit, useful for privileged origins such as Root.
		type CreateOrigin: EnsureOriginWithArg<
			<Self as frame_system::Config>::RuntimeOrigin,
			Self::AssetId,
			Success = Option<Self::AccountId>,
		>;

		/// The aggregated origin, tying the runtime origin to [`Config::PalletsOrigin`] so PSM
		/// admins can be matched against incoming origins.
		type RuntimeOrigin: OriginTrait<PalletsOrigin = Self::PalletsOrigin>
			+ From<Self::PalletsOrigin>
			+ IsType<<Self as frame_system::Config>::RuntimeOrigin>;

		/// The caller origin, overarching type of all pallets' origins. Stored as a PSM's
		/// `full_admin` / `emergency_admin` and matched against incoming origins.
		type PalletsOrigin: Parameter
			+ From<frame_system::RawOrigin<Self::AccountId>>
			+ CallerTrait<Self::AccountId>
			+ MaxEncodedLen;

		/// Asset identifier type.
		type AssetId: Parameter + Member + Clone + MaybeSerializeDeserialize + MaxEncodedLen + Ord;

		/// A type representing the weights required by the dispatchables of this pallet.
		type WeightInfo: WeightInfo;

		/// PalletId for deriving each PSM instance's reserve sub-account.
		#[pallet::constant]
		type PalletId: Get<PalletId>;

		/// Maximum number of approved external assets per PSM instance.
		#[pallet::constant]
		type MaxExternals: Get<u32>;

		/// Helper for benchmarks to create an external asset with correct metadata.
		#[cfg(feature = "runtime-benchmarks")]
		type BenchmarkHelper: crate::BenchmarkHelper<Self::AssetId, Self::AccountId>;
	}
```

**File:** substrate/frame/psm/src/lib.rs (L701-723)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::mint(T::MaxExternals::get()))]
		pub fn mint(
			origin: OriginFor<T>,
			internal_asset: T::AssetId,
			external_asset: T::AssetId,
			external_amount: BalanceOf<T>,
			max_fee: Permill,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let info = Psm::<T>::get(&internal_asset).ok_or(Error::<T>::PsmNotFound)?;

			let external = ExternalAssets::<T>::get(&internal_asset, &external_asset)
				.ok_or(Error::<T>::UnsupportedAsset)?;
			ensure!(external.status.allows_minting(), Error::<T>::MintingStopped);

			let ext_decimals = external.decimals;
			let internal_decimals = info.internal_decimals;

			let internal_equivalent =
				Self::external_to_internal(external_amount, ext_decimals, internal_decimals)?;
			ensure!(!internal_equivalent.is_zero(), Error::<T>::AmountTooSmallAfterConversion);
			ensure!(internal_equivalent >= info.min_swap_amount, Error::<T>::BelowMinimumSwap);
```

**File:** substrate/frame/psm/src/lib.rs (L725-757)
```rust
			let effective_external =
				Self::internal_to_external(internal_equivalent, ext_decimals, internal_decimals)?;

			let fee_rate = MintingFee::<T>::get(&internal_asset, &external_asset);
			ensure!(fee_rate <= max_fee, Error::<T>::FeeTooHigh);
			let fee = fee_rate.mul_ceil(internal_equivalent);
			let internal_to_user = internal_equivalent.saturating_sub(fee);

			let current_total_psm_debt = Self::total_psm_debt(&internal_asset);
			ensure!(
				current_total_psm_debt.saturating_add(internal_equivalent) <= info.max_debt,
				Error::<T>::ExceedsMaxPsmDebt
			);

			let current_debt = PsmDebt::<T>::get(&internal_asset, &external_asset);
			let max_debt = Self::max_asset_debt(&internal_asset, &external_asset, &info);
			let new_debt = current_debt.saturating_add(internal_equivalent);
			ensure!(new_debt <= max_debt, Error::<T>::ExceedsMaxPsmDebt);

			let psm_account = Self::psm_account(&internal_asset);
			T::Fungibles::transfer(
				external_asset.clone(),
				&who,
				&psm_account,
				effective_external,
				Preservation::Expendable,
			)?;
			T::Fungibles::mint_into(internal_asset.clone(), &who, internal_to_user)?;
			if !fee.is_zero() {
				T::Fungibles::mint_into(internal_asset.clone(), &info.fee_destination, fee)?;
			}

			PsmDebt::<T>::insert(&internal_asset, &external_asset, new_debt);
```

**File:** substrate/frame/psm/src/lib.rs (L812-889)
```rust
		pub fn redeem(
			origin: OriginFor<T>,
			internal_asset: T::AssetId,
			external_asset: T::AssetId,
			internal_amount: BalanceOf<T>,
			max_fee: Permill,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let info = Psm::<T>::get(&internal_asset).ok_or(Error::<T>::PsmNotFound)?;

			let external = ExternalAssets::<T>::get(&internal_asset, &external_asset)
				.ok_or(Error::<T>::UnsupportedAsset)?;
			ensure!(external.status.allows_redemption(), Error::<T>::AllSwapsStopped);

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

			let current_debt = PsmDebt::<T>::get(&internal_asset, &external_asset);
			ensure!(current_debt >= effective_internal_net, Error::<T>::InsufficientReserve);

			let reserve = Self::get_reserve(&internal_asset, &external_asset);
			if reserve < external_out {
				defensive!("PSM reserve is less than expected output amount");
				return Err(Error::<T>::Unexpected.into());
			}

			if !fee.is_zero() {
				T::Fungibles::transfer(
					internal_asset.clone(),
					&who,
					&info.fee_destination,
					fee,
					Preservation::Expendable,
				)?;
			}

			if !effective_internal_net.is_zero() {
				T::Fungibles::burn_from(
					internal_asset.clone(),
					&who,
					effective_internal_net,
					Preservation::Expendable,
					Precision::Exact,
					Fortitude::Polite,
				)?;
			}

			let psm_account = Self::psm_account(&internal_asset);
			if !external_out.is_zero() {
				T::Fungibles::transfer(
					external_asset.clone(),
					&psm_account,
					&who,
					external_out,
					Preservation::Expendable,
				)?;
			}

```
