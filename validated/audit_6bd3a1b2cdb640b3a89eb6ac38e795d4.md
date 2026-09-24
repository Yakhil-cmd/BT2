### Title
`add_tip`/`register_token` swap tip/fee assets for Ether with `amount_out_min: None`, exposing users to unbounded slippage/sandwich loss - ([File: bridges/snowbridge/pallets/system-frontend/src/lib.rs])

### Summary
`pallet-snowbridge-system-frontend`'s `swap_and_burn` helper — invoked from the signed, user-facing `add_tip` extrinsic and from `register_token` — swaps a user-supplied fee/tip asset for Ether via `pallet_asset_conversion`'s `Swap` trait, but hardcodes the slippage-protection parameter to `None`, i.e. "no minimum amount required." This is a direct FRAME analog of the Talos/Uniswap V3 finding: a real, unprivileged, signed entry point performs an AMM swap with zero slippage control, letting MEV/sandwich actors extract value at the user's expense.

### Finding Description
`add_tip` is a signed extrinsic (`ensure_signed(origin)?`) that lets any user attach a tip (in an arbitrary fungible asset) to a bridged message: [1](#0-0) 

It calls `swap_fee_asset_and_burn`, which for any non-Ether asset calls `swap_and_burn`: [2](#0-1) 

`swap_and_burn` performs the actual AMM swap via the `Swap` trait's `swap_exact_tokens_for_tokens`, explicitly passing `None` for `amount_out_min` with the comment "No minimum amount required": [3](#0-2) 

The `Swap` trait's `swap_exact_tokens_for_tokens` is designed to accept an `Option<Balance>` slippage bound specifically to let the caller "return an error if it is unable to acquire the amount desired": [4](#0-3) 

and the pallet's own implementation only enforces the check `amount_out >= amount_out_min` when `Some` is supplied: [5](#0-4) 

By passing `None`, `system-frontend` deliberately disables this protection — mirroring exactly the Uniswap V3 finding's root cause of setting `amount0Min`/`amount1Min` to `0`. `T::Swap` is wired in production to the real `pallet_asset_conversion::Pallet` on Asset Hub Westend's bridge-to-Ethereum configuration (`type Swap = ...` in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/bridge_to_ethereum_config.rs`), so this reaches a live AMM pool with real reserves, not a mock.

`register_token` similarly reaches this same unprotected swap path for non-root origins: [6](#0-5) 

### Impact Explanation
Because `amount_out_min` is `None`, the swap can execute at an arbitrarily bad price if the pool has been manipulated immediately beforehand (classic sandwich attack) or if the pool is thin/illiquid. The `ether_gained` value directly determines:
- the `amount` field forwarded to `RegisterToken` on the BridgeHub (used to fund message-registration costs on Ethereum), and
- the tip amount credited via `AddTip` to reward relayers for delivering the bridged message.

A user calling `add_tip` (or `register_token`) can have most of their supplied asset value siphoned off by an attacker sandwiching the swap, receiving far less Ether-equivalent value credited toward their tip/registration than expected — a direct, measurable loss of user funds, analogous to the Medium-severity Talos finding. This does not require any privileged role: it is triggerable by any account holding the relevant fungible asset and calling a public, fee-paying extrinsic.

### Likelihood Explanation
Likelihood is realistic but bounded: the attacker needs the pool for `(tip_asset, Ether-representative-asset)` to have exploitable depth/thinness relative to the tip amount, and needs to win the sandwich race against the target transaction (front-run + back-run), which is standard practice for MEV searchers on chains with public mempools/ordering. No governance, validator collusion, or privileged access is required — matching the "no privileged prerequisites" bar for this scan. The bug is a hardcoded design choice (`None`), not an edge case, so it triggers on every non-Ether tip/fee swap.

### Recommendation
Add a caller-supplied (or conservatively-computed, e.g. quoted-price-minus-tolerance) `amount_out_min` parameter to `add_tip` and `register_token`, and thread it through `swap_fee_asset_and_burn`/`swap_and_burn` into `Swap::swap_exact_tokens_for_tokens` instead of hardcoding `None`. At minimum, derive a bound from `AssetConversionApi::quote_price_exact_tokens_for_tokens` at call time with a configurable slippage tolerance, and fail the extrinsic (returning `Error::SwapError`) if the AMM cannot honor it, rather than silently accepting any output amount.

### Proof of Concept
No executable local reproduction was run (environment access to build/run the Snowbridge test harness was not available in this session); the finding is based on static code tracing through the exact call chain (`add_tip` → `swap_fee_asset_and_burn` → `swap_and_burn` → `Swap::swap_exact_tokens_for_tokens(..., None, ...)`) and confirmation that the enforced check `amount_out >= amount_out_min` in `pallet_asset_conversion::do_swap_exact_tokens_for_tokens` is skipped entirely when `amount_out_min` is `None`. A full PoC would require standing up the `snowbridge-system-frontend` mock/test runtime (already present at `bridges/snowbridge/pallets/system-frontend/src/mock.rs`, which wires `type Swap` to `pallet_asset_conversion`), seeding a thin pool, sandwiching an `add_tip` call with a manipulating swap in the same block, and asserting `ether_gained` is far below the pre-manipulation quote — this exact test does not currently exist in the repository (existing tests only cover the happy path and error branches such as `SwapError`, `TipAmountZero`, not slippage/MEV scenarios), so this was not executed and no pass/fail result can be reported.

### Citations

**File:** bridges/snowbridge/pallets/system-frontend/src/lib.rs (L225-252)
```rust
		pub fn register_token(
			origin: OriginFor<T>,
			asset_id: Box<VersionedLocation>,
			metadata: AssetMetadata,
			fee_asset: Asset,
		) -> DispatchResult {
			ensure!(!Self::export_operating_mode().is_halted(), Error::<T>::Halted);

			let asset_location: Location =
				(*asset_id).try_into().map_err(|_| Error::<T>::UnsupportedLocationVersion)?;
			let origin_location = T::RegisterTokenOrigin::ensure_origin(origin, &asset_location)?;

			let ether_gained = if origin_location.is_here() {
				// Root origin/location does not pay any fees/tip.
				0
			} else {
				Self::swap_fee_asset_and_burn(origin_location.clone(), fee_asset)?
			};

			let call = Self::build_register_token_call(
				origin_location.clone(),
				asset_location,
				metadata,
				ether_gained,
			)?;

			Self::send_transact_call(origin_location, call)
		}
```

**File:** bridges/snowbridge/pallets/system-frontend/src/lib.rs (L261-273)
```rust
		pub fn add_tip(origin: OriginFor<T>, message_id: MessageId, asset: Asset) -> DispatchResult
		where
			<T as frame_system::Config>::AccountId: Into<Location>,
		{
			let who = ensure_signed(origin)?;

			let ether_gained = Self::swap_fee_asset_and_burn(who.clone().into(), asset)?;

			// Send the tip details to BH to be allocated to the reward in the Inbound/Outbound
			// pallet
			let call = Self::build_add_tip_call(who.clone(), message_id.clone(), ether_gained);
			Self::send_transact_call(who.into(), call)
		}
```

**File:** bridges/snowbridge/pallets/system-frontend/src/lib.rs (L290-317)
```rust
		fn swap_and_burn(
			origin: Location,
			tip_asset_location: Location,
			ether_location: Location,
			tip_amount: u128,
		) -> Result<u128, DispatchError> {
			// Swap tip asset to ether
			let swap_path = vec![tip_asset_location.clone(), ether_location.clone()];
			let who = T::AccountIdConverter::convert_location(&origin)
				.ok_or(Error::<T>::LocationConversionFailed)?;

			let ether_gained = T::Swap::swap_exact_tokens_for_tokens(
				who.clone(),
				swap_path,
				tip_amount,
				None, // No minimum amount required
				who,
				true,
			)?;

			// Burn the ether
			let ether_asset = Asset::from((ether_location.clone(), ether_gained));

			burn_for_teleport::<T::AssetTransactor>(&origin, &ether_asset)
				.map_err(|_| Error::<T>::BurnError)?;

			Ok(ether_gained)
		}
```

**File:** bridges/snowbridge/pallets/system-frontend/src/lib.rs (L372-404)
```rust
		fn swap_fee_asset_and_burn(
			origin: Location,
			fee_asset: Asset,
		) -> Result<u128, DispatchError> {
			let ether_location = T::EthereumLocation::get();
			let (fee_asset_location, fee_amount) = match fee_asset {
				Asset { id: AssetId(ref loc), fun: Fungible(amount) } => (loc, amount),
				_ => {
					tracing::debug!(target: LOG_TARGET, ?fee_asset, "error matching fee asset");
					return Err(Error::<T>::UnsupportedAsset.into());
				},
			};
			if fee_amount == 0 {
				return Ok(0);
			}

			let ether_gained = if *fee_asset_location != ether_location {
				Self::swap_and_burn(
					origin.clone(),
					fee_asset_location.clone(),
					ether_location,
					fee_amount,
				)
				.inspect_err(|&e| {
					tracing::debug!(target: LOG_TARGET, ?e, "error swapping asset");
				})?
			} else {
				burn_for_teleport::<T::AssetTransactor>(&origin, &fee_asset)
					.map_err(|_| Error::<T>::BurnError)?;
				fee_amount
			};
			Ok(ether_gained)
		}
```

**File:** substrate/frame/asset-conversion/src/swap.rs (L33-50)
```rust
	/// Swap exactly `amount_in` of asset `path[0]` for asset `path[last]`.
	/// If an `amount_out_min` is specified, it will return an error if it is unable to acquire
	/// the amount desired.
	///
	/// Withdraws the `path[0]` asset from `sender`, deposits the `path[last]` asset to `send_to`,
	/// respecting `keep_alive`.
	///
	/// If successful, returns the amount of `path[last]` acquired for the `amount_in`.
	///
	/// This operation is expected to be atomic.
	fn swap_exact_tokens_for_tokens(
		sender: AccountId,
		path: Vec<Self::AssetKind>,
		amount_in: Self::Balance,
		amount_out_min: Option<Self::Balance>,
		send_to: AccountId,
		keep_alive: bool,
	) -> Result<Self::Balance, DispatchError>;
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L988-1002)
```rust
			ensure!(amount_in > Zero::zero(), Error::<T>::ZeroAmount);
			if let Some(amount_out_min) = amount_out_min {
				ensure!(amount_out_min > Zero::zero(), Error::<T>::ZeroAmount);
			}

			Self::validate_swap_path(&path)?;
			let path = Self::balance_path_from_amount_in(amount_in, path)?;

			let amount_out = path.last().map(|(_, a)| *a).ok_or(Error::<T>::InvalidPath)?;
			if let Some(amount_out_min) = amount_out_min {
				ensure!(
					amount_out >= amount_out_min,
					Error::<T>::ProvidedMinimumNotSufficientForSwap
				);
			}
```
