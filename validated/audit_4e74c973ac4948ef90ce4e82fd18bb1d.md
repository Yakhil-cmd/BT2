### Title
`pallet-psm` mints/redeems stablecoins at a fixed 1:1 ratio with no price-deviation check, letting the first mover extract value during a USDC/USDT de-peg - (File: substrate/frame/psm/src/lib.rs)

### Summary
The report describes `SpotHedgeBaseMaker` pricing USDT/USDC collateral as always worth exactly $1 (via a `<base>/USD` oracle instead of a `<base>/<quote>` oracle), so during a de-peg the first LP to act can withdraw more value than it deposited, at the expense of later LPs. `substrate/frame/psm/src/lib.rs` implements a Peg Stability Module (`pallet-psm`) with the identical root cause: `mint`/`redeem` convert between an "internal" stablecoin and "external" stablecoins (e.g. USDC/USDT) purely by rescaling decimals (`external_to_internal`/`internal_to_external`), never consulting any price oracle. Any signed, unprivileged account can call these extrinsics.

### Finding Description
`Pallet::mint` [1](#0-0)  takes `external_amount` of an approved external asset, converts it to an "internal equivalent" using only decimal scaling via `external_to_internal`, and mints that many internal stablecoins to the caller (minus a fixed fee). `Pallet::redeem` [2](#0-1)  does the reverse, again using only `internal_to_external` decimal conversion. Neither function reads a price oracle or has any on-chain check that the external asset is actually trading at parity with the internal stablecoin. The pallet's own documentation confirms this is a deliberate 1:1 design: "Instantiable Peg Stability Modules (PSMs). Each PSM enables 1:1 swaps between an internal stablecoin and one or more approved external stablecoins" [3](#0-2) , and the README states the same [4](#0-3) .

The only defense against a de-pegged external asset is a manually-triggered `CircuitBreakerLevel` (`AllEnabled`/`MintingDisabled`/`AllDisabled`) set by a governance-controlled `Emergency`/`Full` admin via `set_asset_status` [5](#0-4)  — there is no automatic, price-based safeguard. This is structurally identical to the `SpotHedgeBaseMaker` bug: the protocol values a collateral/quote asset at a fixed 1:1 rate instead of its live market price, so during an actual de-peg the first unprivileged user to `mint`/`redeem` can extract more value than their deposit is worth, leaving the PSM's reserve permanently under-collateralized relative to outstanding internal-asset debt, at the expense of everyone who redeems afterward.

### Impact Explanation
If an approved external asset (e.g. USDC) de-pegs downward (say to $0.90), any signed user can call `mint` to deposit the de-pegged USDC and receive internal stablecoin at full 1:1 value (minus the ~0.5% fee) [6](#0-5) . They can then redeem that internal stablecoin elsewhere (another external asset in the same PSM, or on a secondary market) near par, realizing an arbitrage gain funded by the PSM's reserve/other holders — while the PSM now holds devalued collateral backing at-par debt. Symmetrically, if the external asset de-pegs upward, a user can `redeem` internal stablecoin for external asset at 1:1 and immediately profit by selling the withdrawn external asset above $1. Either direction transfers value from the PSM's remaining internal-asset holders/reserve to the first mover, matching the impact class described in the source report (first-mover extraction during a de-peg, "leaving less for all others"). This was rated Medium and acknowledged by the original protocol team, and the same severity classification is appropriate here since it requires an external market condition (a real de-peg) rather than a purely on-chain exploit, and depends on the size of `max_debt`/ceilings and how quickly the `Emergency` admin reacts.

### Likelihood Explanation
Likelihood is Medium: it requires an actual de-peg event of an approved external stablecoin, which is an external market condition outside the pallet's control (as in the original report). No privileged role, governance action, or malicious node/validator is needed by the attacker — `mint`/`redeem` are open to any `ensure_signed` account [7](#0-6) [8](#0-7) . The only mitigation is manual, reactive (governance must notice the de-peg and call `set_asset_status` before damage occurs), which is the same limitation acknowledged in the source report for `SpotHedgeBaseMaker`.

### Recommendation
Integrate a price check (e.g. via `pallet-oracle`, which already exists in this monorepo, see `substrate/frame/honzon/oracle`) so `mint`/`redeem` either reject swaps when the external asset's oracle price deviates from the internal asset's peg by more than a configurable tolerance, or scale the conversion by the live price ratio instead of a fixed 1:1/decimals-only conversion. Alternatively, add an automatic, price-triggered circuit breaker rather than relying solely on a manually-invoked `Emergency` admin action.

### Proof of Concept
No live execution was performed — this environment provides read-only codebase search/inspection tools only (no filesystem/terminal access), so no test was run and no result is claimed. Evidence for the finding is drawn directly from the pallet source and its own documentation:
- Fixed decimal-only conversion functions `external_to_internal`/`internal_to_external` are used in both `mint` and `redeem` with no oracle input [9](#0-8) [10](#0-9) .
- No oracle/price dependency appears anywhere in `pallet-psm`'s `Config` trait [11](#0-10) .
- The pallet ships an existing test harness (`substrate/frame/psm/src/tests.rs`, e.g. the mint/redeem round-trip assertions around lines 2183–2224) that a Devin agent with terminal access could extend with a scenario simulating a de-pegged external asset (mint with discounted external asset, then redeem via a second external asset at full value) to concretely demonstrate the value extraction; this was not executed here due to tool limitations. [12](#0-11)

### Citations

**File:** substrate/frame/psm/src/lib.rs (L18-21)
```rust
//! # Peg Stability Module (PSM) Pallet
//!
//! Instantiable Peg Stability Modules (PSMs). Each PSM enables 1:1 swaps between an internal
//! stablecoin and one or more approved external stablecoins, typically to maintain a peg.
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

**File:** substrate/frame/psm/src/lib.rs (L703-757)
```rust
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
```

**File:** substrate/frame/psm/src/lib.rs (L812-903)
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

			PsmDebt::<T>::mutate(&internal_asset, &external_asset, |debt| {
				*debt = debt.saturating_sub(effective_internal_net);
			});

			Self::deposit_event(Event::Redeemed {
				who,
				internal_asset,
				external_asset,
				internal_consumed: effective_internal_net.saturating_add(fee),
				external_received: external_out,
				internal_fee: fee,
			});
			Ok(())
		}
```

**File:** substrate/frame/psm/README.md (L1-5)
```markdown
# PSM Pallet

A module hosting one or more Peg Stability Modules. Each PSM enables 1:1 swaps
between a specific internal stablecoin and that PSM's pre-approved external
assets on Substrate-based blockchains.
```

**File:** substrate/frame/psm/README.md (L93-105)
```markdown
## Circuit Breaker

Each approved external on each instance has an independent circuit breaker
with three levels:

| Level             | Minting | Redemption | Use Case                          |
| ----------------- | ------- | ---------- | --------------------------------- |
| `AllEnabled`      | Allowed | Allowed    | Normal operation                  |
| `MintingDisabled` | Blocked | Allowed    | Drain debt from a problematic external |
| `AllDisabled`     | Blocked | Blocked    | Full emergency halt of an external |

`set_asset_status` is callable at both the `Full` (`full_admin`) and
`Emergency` (`emergency_admin`) levels.
```

**File:** substrate/frame/psm/src/tests.rs (L2207-2222)
```rust
			// Assertions
			// 1. IF balance increased by total fees (mint fees + redeem fees)
			assert_eq!(if_increase, total_fees, "IF should receive all fees");

			// 2. PSM external balance equals what remained after redemptions
			assert_eq!(psm_external_after, psm_debt_after, "PSM external = PSM debt");

			// 3. User external decrease equals total fees paid
			assert_eq!(user_decrease, total_fees, "User loss equals fees");

			// 4. PSM debt equals PSM external asset balance
			assert_eq!(
				psm_debt_after,
				get_asset_balance(USDC_ASSET_ID, psm_account()),
				"PSM debt equals PSM external balance"
			);
```
