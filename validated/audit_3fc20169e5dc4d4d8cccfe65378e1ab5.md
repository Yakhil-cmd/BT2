This confirms `external_to_internal`/`internal_to_external` in `substrate/frame/psm/src/lib.rs` only perform decimal scaling — no price check whatsoever — which is a stronger version of the audited bug class (assuming fixed peg parity for an external asset used as "collateral" backing).

### Title
Peg Stability Module (`pallet-psm`) mints internal stablecoin 1:1 against depegged external assets with no price oracle check - (File: substrate/frame/psm/src/lib.rs)

### Summary
`pallet-psm::mint` and `pallet-psm::redeem` swap between an internal stablecoin and admin-approved "external" assets (e.g. USDC, USDT) purely via decimal scaling (`external_to_internal`/`internal_to_external`), with zero price verification. Any signed account can call `mint` to deposit an external asset and receive the internal stablecoin at a hardcoded 1:1 nominal rate. If the external asset depegs below its intended $1 value (e.g. a USDC-style depeg event, or any similarly-approved asset whose peg breaks due to bridge/custodian compromise), the pallet still treats it as fully backing the internal stablecoin unit-for-unit, exactly analogous to the reported JOJO/JUSD issue where a BTC/USD Chainlink price was applied to WBTC without accounting for depeg risk between WBTC and BTC.

### Finding Description
`Pallet::mint` at [1](#0-0)  takes attacker-supplied `external_asset` and `external_amount`, converts to `internal_equivalent` via `Self::external_to_internal`, and mints that amount of `internal_asset` to the caller minus a fixed fee — with no reference to any market price or oracle, only decimal-based scaling. The pallet doc explicitly states the design assumption: "Each PSM instance ... backed 1:1 by external assets in that PSM's reserve" [2](#0-1) . The only safety controls are governance-set per-asset debt ceilings/weights and a `CircuitBreakerLevel` that an admin can flip to `MintingDisabled`/`AllDisabled` [3](#0-2)  — reactive controls, not preventive price checks. There is no `Config` type or storage item referencing an oracle or price feed anywhere in the pallet; `Config` only wires `Fungibles`, `Consideration`, `CreateOrigin`, `PalletId`, and `MaxExternals` [4](#0-3) .

This mirrors the reported invariant violation: the protocol assumes an external asset maintains a hard peg to the internal stablecoin's unit of account without validating that assumption against real market price, exactly like assuming WBTC == BTC via a BTC/USD Chainlink feed. Here it's actually stricter/worse — not even an oracle is consulted, just a static decimal conversion.

### Impact Explanation
If a governance-approved external asset (e.g. a bridged/wrapped stablecoin) depegs downward — due to a bridge compromise, custodian insolvency, or de-anchoring event — any unprivileged signed account can call `mint` to swap the now-cheap external asset for full-value internal stablecoin at the stale 1:1 rate, up to the per-asset/aggregate debt ceiling [5](#0-4) . This extracts real value from the PSM reserve and mints unbacked internal stablecoin, directly reducing the internal asset's actual backing ratio — an unbacked issuance / protocol insolvency risk matching the reported severity class. The only stopgap is a `full_admin`/`emergency_admin` manually noticing the depeg and setting the circuit breaker to `MintingDisabled`, which is reactive and depends on off-chain monitoring, leaving a window of exploitation identical in nature to the reported issue.

### Likelihood Explanation
Any external asset approved on a PSM instance is attacker-reachable through the public, permissionless `mint`/`redeem` extrinsics — no privileged role, governance control, or stolen keys are needed by the caller. Likelihood is entirely tied to whether a runtime integrator approves a bridged/wrapped or otherwise de-peggable asset as a PSM external, which is a normal expected configuration for this pallet's stated purpose (accepting USDC/USDT-like externals).

### Recommendation
Before or during `mint`/`redeem`, cross-check the external asset's live market price against its assumed peg (e.g., via `pallet-oracle`, already present in this runtime at `substrate/bin/node/runtime/src/lib.rs` pallet index 85) and reject or adjust conversions if the deviation exceeds a configurable tolerance band, rather than relying solely on decimal-only conversion and a manually-triggered circuit breaker.

### Proof of Concept
No executable PoC was run against a live network. The logical reproduction path is: (1) a runtime approves external asset `X` on a PSM instance via `add_external_asset`; (2) `X` depegs on secondary markets (attacker acquires `X` cheaply off-chain); (3) attacker calls `Pallet::mint(origin, internal_asset, X, external_amount, max_fee)`, which performs only `external_to_internal` decimal scaling with no price check [6](#0-5)  and mints full nominal-value internal stablecoin to the attacker; (4) protocol reserve is now under-backed relative to outstanding internal-asset debt. This is a direct code-path/config analysis rather than a live test execution.

### Citations

**File:** substrate/frame/psm/src/lib.rs (L59-61)
```rust
//! * **Reserve**: External asset balance held by a PSM's reserve account (derived, not stored).
//! * **PSM Debt**: Total internal asset minted through a PSM, backed 1:1 by external assets in that
//!   PSM's reserve.
```

**File:** substrate/frame/psm/src/lib.rs (L167-187)
```rust
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

**File:** substrate/frame/psm/src/lib.rs (L701-768)
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

			Self::deposit_event(Event::Minted {
				who,
				internal_asset,
				external_asset,
				external_consumed: effective_external,
				internal_received: internal_to_user,
				internal_fee: fee,
			});
			Ok(())
		}
```
