### Title
`add_tip` extrinsic in `snowbridge-pallet-system-frontend` swaps user's tip asset with hardcoded zero slippage protection, causing loss of user funds - ([File: bridges/snowbridge/pallets/system-frontend/src/lib.rs])

### Summary
The `add_tip` extrinsic in `pallet_snowbridge_system_frontend` lets any signed user attach an arbitrary fungible `Asset` as a relayer tip for a bridge message. Internally, this tip is swapped into Ether via `pallet_asset_conversion` (through the abstract `Swap` trait) so it can be burned/teleported to Ethereum. The swap call hardcodes `amount_out_min` to `None`, meaning no minimum-output/slippage protection is ever applied on the user's behalf, mirroring the reported EVM bug where `slippage` is hardcoded to `0` in a bridging `xcall`.

### Finding Description
`Pallet::add_tip` is a public, signed extrinsic: [1](#0-0) 

It calls `swap_fee_asset_and_burn`, which for any non-Ether tip asset delegates to `swap_and_burn`: [2](#0-1) 

`swap_and_burn` invokes `T::Swap::swap_exact_tokens_for_tokens` with the minimum-output parameter explicitly hardcoded to `None`, annotated "No minimum amount required": [3](#0-2) 

The underlying `pallet_asset_conversion` swap implementation does support a caller-supplied `amount_out_min` and enforces it via `ProvidedMinimumNotSufficientForSwap` when set: [4](#0-3) [5](#0-4) 

But the `system-frontend` pallet never exposes this parameter to callers of `add_tip` (or `register_token`, which follows the same path) — it always passes `None`, exactly the same class of bug as the reported Solidity `Satellite.sol` code hardcoding Connext's `slippage` argument to `0` and denying the user any way to bound their price impact.

### Impact Explanation
Because the user cannot specify (or even estimate on-chain) a minimum acceptable Ether output, and the swap executes against `pallet_asset_conversion`'s live constant-product AMM pool priced at execution time, any attacker (or ordinary market volatility/thin-liquidity condition) can cause the tip-asset→Ether swap to execute at an arbitrarily bad price. The user's tip asset can be swapped for far less Ether than a fair market rate would yield, directly reducing the value of their intended relayer tip and constituting a loss of user funds through the guaranteed-acceptance-of-any-price behavior of `swap_exact_tokens_for_tokens` when `amount_out_min = None`. This is a direct funds-loss defect reachable by any signed account with no privileged role, matching the report's "Hard coded slippage will cause a loss of funds for a user" pattern.

### Likelihood Explanation
Every call to `add_tip` with a non-Ether tip asset goes through this code path unconditionally; there is no configuration flag or opt-in that could avoid it. Exploitability does not require a malicious relayer, governance, or forged state — only normal pool conditions (thin liquidity, temporary price movement, or an attacker front-running the pool with their own swap to move the price before the victim's `add_tip` executes) are needed to realize meaningful loss. This makes the likelihood of realizable loss moderate-to-high whenever the pallet is deployed with real liquidity pools (as it is wired into `asset-hub-westend`'s `bridge_to_ethereum_config.rs`).

### Recommendation
Add a caller-supplied slippage/minimum-output parameter to `add_tip` (and `register_token`'s optional swap) and thread it through `swap_fee_asset_and_burn` → `swap_and_burn` into `T::Swap::swap_exact_tokens_for_tokens` as `Some(amount_out_min)` instead of the hardcoded `None`. Alternatively, derive a safe minimum from a runtime-queried price oracle/quote (`quote_price_exact_tokens_for_tokens`) with a bounded tolerance, so unattended/no-slippage swaps cannot execute at an arbitrarily poor price.

### Proof of Concept
No executable PoC was run; this is a static code-path analysis. The relevant guard failure is structural and directly visible: `swap_and_burn` passes `None` for `amount_out_min` unconditionally at `bridges/snowbridge/pallets/system-frontend/src/lib.rs:305`, bypassing the `ProvidedMinimumNotSufficientForSwap` check that `pallet_asset_conversion::do_swap_exact_tokens_for_tokens` would otherwise enforce (`substrate/frame/asset-conversion/src/lib.rs:997-1002`). Confirming real-network wiring (i.e., that `asset-hub-westend`'s `bridge_to_ethereum_config.rs` `type Swap = ...` binds to the live `pallet_asset_conversion` AMM used for DOT/WETH pools with attacker-manipulable depth) requires reading the full `bridge_to_ethereum_config.rs` file, which the index only partially surfaced (6 matches for `Swap`/`AssetConversion`/`EthereumSystemFrontend` but full content wasn't retrievable in this session) — deployment status and exact pool identity should be verified directly in that file, and a live/emulated-network test (e.g., extending the existing `snowbridge_v2_outbound.rs` integration test suite) executing `add_tip` against a thin pool would provide concrete before/after balance evidence of the loss.

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

**File:** bridges/snowbridge/pallets/system-frontend/src/lib.rs (L301-308)
```rust
			let ether_gained = T::Swap::swap_exact_tokens_for_tokens(
				who.clone(),
				swap_path,
				tip_amount,
				None, // No minimum amount required
				who,
				true,
			)?;
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

**File:** substrate/frame/asset-conversion/src/lib.rs (L987-1002)
```rust
		) -> Result<T::Balance, DispatchError> {
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

**File:** substrate/frame/asset-conversion/src/swap.rs (L43-50)
```rust
	fn swap_exact_tokens_for_tokens(
		sender: AccountId,
		path: Vec<Self::AssetKind>,
		amount_in: Self::Balance,
		amount_out_min: Option<Self::Balance>,
		send_to: AccountId,
		keep_alive: bool,
	) -> Result<Self::Balance, DispatchError>;
```
