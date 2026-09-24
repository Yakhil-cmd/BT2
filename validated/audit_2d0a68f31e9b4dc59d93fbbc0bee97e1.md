### Title
No slippage control on tip-asset swap in `snowbridge-pallet-system-frontend::add_tip` - (File: `bridges/snowbridge/pallets/system-frontend/src/lib.rs`)

### Summary
The `add_tip` extrinsic (and `register_token` for non-root origins) in the Snowbridge system-frontend pallet swaps a caller-supplied tip asset for Ether via `pallet_asset_conversion::Swap::swap_exact_tokens_for_tokens`, but hardcodes `amount_out_min` to `None`, disabling any slippage protection whatsoever on an AMM swap that a signed, unprivileged user triggers. [1](#0-0) 

### Finding Description
`add_tip` is a public, signed extrinsic — any account can call it: `let who = ensure_signed(origin)?;` — with an attacker/user-controlled `asset: Asset` (both the asset location/kind and the `Fungible(amount)` tip amount are caller-supplied). [2](#0-1) 

It calls `Self::swap_fee_asset_and_burn(who.clone().into(), asset)?`, which — when the fee asset differs from the configured `EthereumLocation` — calls `Self::swap_and_burn(...)`: [3](#0-2) 

`swap_and_burn` performs the actual AMM swap through `T::Swap::swap_exact_tokens_for_tokens`, but explicitly passes `None` for the minimum-output parameter, with the comment `// No minimum amount required`:
```rust
let ether_gained = T::Swap::swap_exact_tokens_for_tokens(
    who.clone(),
    swap_path,
    tip_amount,
    None, // No minimum amount required
    who,
    true,
)?;
``` [4](#0-3) 

The `Swap` trait implementation in `pallet-asset-conversion` treats `amount_out_min: None` as "accept any output amount", only rejecting the swap if it strictly evaluates to `Some(amount_out_min)` and the check `amount_out >= amount_out_min` fails: [5](#0-4) 

This is the same class of bug described in the source report: an operation that swaps assets through an AMM/DEX omits enforceable minimum-output ("slippage") protection, allowing a block producer/searcher to sandwich the transaction (front-run the pool state to worsen the price, execute the tip swap at that unfavorable price, then back-run to restore/extract the price difference), extracting value from the swap that the user/protocol would otherwise have kept. Unlike the report's contract, this is not even a user-supplied "0 slippage" — the protocol code itself unconditionally disables the check for every `add_tip` call, so there is no way for the caller to opt into protection.

### Impact Explanation
Every `add_tip` call (and every non-root `register_token` call) that swaps a non-Ether tip asset is exposed to unconditional MEV/sandwich extraction with zero minimum-output enforcement, so an attacker (any actor able to order transactions relative to this extrinsic, e.g., a block-authoring collator or a searcher submitting priority transactions) can capture essentially all of the AMM slippage/price-impact value from the swap, at the direct expense of the account funding the tip. Because the result (`ether_gained`) also determines the tip amount reported to the bridge-hub reward pallet via `build_add_tip_call`, an artificially low `ether_gained` also silently reduces the on-chain-recorded relayer tip/reward, degrading protocol incentives beyond just the swapper's individual loss.

### Likelihood Explanation
High — `add_tip` is a normal, permissionless, signed extrinsic with no special preconditions; the vulnerable code path (`swap_and_burn`) is hit any time the tip asset is not already Ether, which is the expected common case for users tipping in a local/native asset. No privileged role, governance action, or malicious infrastructure component is required — only ordinary transaction-ordering advantage (collator inclusion order or a searcher paying more for priority), consistent with the scope's allowed threat model.

### Recommendation
Do not hardcode `None` for `amount_out_min` in `swap_and_burn`. Either:
- Add a caller-supplied `min_amount_out`/slippage-bound parameter to `add_tip`/`register_token` and thread it through to `T::Swap::swap_exact_tokens_for_tokens`, or
- Compute an on-chain minimum via `AssetConversionApi::quote_price_exact_tokens_for_tokens`/`quote_price_tokens_for_exact_tokens` (or the pool's spot price) at call time with a bounded, protocol-defined maximum acceptable slippage, and pass `Some(computed_min)` instead of `None`.

### Proof of Concept
No executable PoC was run against a live network or test harness; this analysis is based on static code review of the production pallet source. The chain of evidence supporting the vulnerability is:
1. `add_tip` accepts a signed, unprivileged origin and attacker-controlled `asset` argument: [2](#0-1) .
2. It unconditionally routes through `swap_fee_asset_and_burn` → `swap_and_burn` whenever the fee asset isn't already the Ether location: [3](#0-2) .
3. `swap_and_burn` calls the real AMM swap entry point with `amount_out_min = None`: [4](#0-3) .
4. The underlying `pallet-asset-conversion` swap logic only enforces a minimum when `Some(_)` is supplied, confirmed by both the implementation and its own test suite explicitly exercising `ProvidedMinimumNotSufficientForSwap` only when a `Some` bound is violated: [5](#0-4) [6](#0-5) .

I was not able to fully confirm within this session the exact concrete binding of `T::Swap` in the `asset-hub-westend` runtime configuration (`bridges/snowbridge/pallets/system-frontend` is wired via `cumulus/parachains/runtimes/assets/asset-hub-westend/src/bridge_to_ethereum_config.rs`, which does reference `type Swap` and the `SnowbridgeSystemFrontend` pallet, but I did not read the full file contents to verify it binds to the live `pallet_asset_conversion::Pallet<Runtime>` versus a wrapper/mock). This should be verified with a Devin session that has full file access before treating this as bounty-final, since eligibility depends on confirming the real production runtime wiring (not just the pallet crate in isolation) and the currently deployed/active program scope for Snowbridge.

### Citations

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

**File:** substrate/frame/asset-conversion/src/tests.rs (L1600-1613)
```rust
		let exchange_amount = 100;

		assert_noop!(
			AssetConversion::swap_exact_tokens_for_tokens(
				RuntimeOrigin::signed(user),
				bvec![token_2.clone(), token_1.clone()],
				exchange_amount, // amount_in
				4000,            // amount_out_min
				user,
				false,
			),
			Error::<Test>::ProvidedMinimumNotSufficientForSwap
		);
	});
```
