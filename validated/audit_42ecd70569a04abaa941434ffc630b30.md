Found a direct analog. Asset Hub Rococo's `NonTransfer` proxy filter is a deny-list that omits `pallet_asset_conversion`'s `RuntimeCall::AssetConversion` variant, unlike Asset Hub Westend where this exact gap was patched (PR #12771). This lets a delegate holding only a restricted `NonTransfer` proxy grant execute swaps on the delegator's behalf while fully controlling the slippage parameter — the same abuse pattern as the reported `MarginDex.swap_margin()` issue.

### Title
`ProxyType::NonTransfer` fails to deny `AssetConversion` swaps on Asset Hub Rococo, letting a restricted delegate drain the delegator's assets via attacker-chosen slippage - ([File: cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs])

### Summary
`pallet-proxy` lets an account grant a delegate a restricted `ProxyType::NonTransfer` proxy, documented to permit "any call that does not transfer funds or assets." On Asset Hub Rococo the `InstanceFilter<RuntimeCall>::filter` implementation for `NonTransfer` is a deny-list that lists only `Balances`, `Assets`, `NftFractionalization`, `Nfts`, `Uniques` as forbidden call families, but omits `RuntimeCall::AssetConversion`. Because `pallet_asset_conversion::Call::swap_exact_tokens_for_tokens`/`swap_tokens_for_exact_tokens` are dispatched with the *proxied real account* as `sender` and the delegate fully controls `amount_out_min`/`amount_in_max`, a `NonTransfer` delegate can force the delegator to execute a swap with attacker-chosen (near-zero) slippage protection, extracting value via front-running/sandwiching — the same root cause as the reported `MarginDex.swap_margin()` bug where a delegate could bypass slippage protection on a victim's funds. Asset Hub Westend fixed the identical gap in `prdoc/pr_12771.prdoc`, explicitly calling out `AssetConversion` as a call family that "moves the caller's assets" and must be denied to `NonTransfer`; Asset Hub Rococo's equivalent filter was never updated.

### Finding Description
`pallet-proxy::proxy()` dispatches the wrapped call with the `real` (delegator) account as origin after checking `T::ProxyType::filter` [1](#0-0) . The Asset Hub Rococo `ProxyType::filter` implementation for `NonTransfer` denies only a fixed list of pallets and fails open for everything else: [2](#0-1) 

`RuntimeCall::AssetConversion` is not in that deny list, so it is dispatchable by a `NonTransfer` proxy. The dispatched call withdraws `path[0]` from the proxied `sender` (the delegator, since `ensure_signed(origin)` resolves to the `real` account under proxy dispatch) and only requires `amount_out >= amount_out_min` where `amount_out_min` is supplied by the caller — here the delegate: [3](#0-2) [4](#0-3) 

Because the delegate — not the delegator — chooses `amount_out_min`, they can pass `1` (or any negligible value), removing the only slippage safeguard the pallet provides, then extract value from the delegator's swap through front-running/sandwiching the pool, exactly mirroring the Vyper report's `swap_margin(_account, ..., _min_amount_out)` where the delegate controls `_min_amount_out` on the victim's behalf.

Asset Hub Westend's `ProxyType::NonTransfer` explicitly denies `RuntimeCall::AssetConversion(..)` with the comment "Swaps and liquidity provision move the caller's assets," fixed via `prdoc/pr_12771.prdoc`: [5](#0-4) [6](#0-5) 

Asset Hub Rococo runs the same `pallet_asset_conversion` pallet (confirmed present in its `construct_runtime!`), but its `NonTransfer` filter was never updated to match, leaving the identical gap open there.

### Impact Explanation
A delegator who grants a `NonTransfer` proxy — believing per pallet documentation that the delegate cannot move their funds/assets — is exposed to unbounded value extraction through unprotected swaps. The delegate can time the call to sandwich the delegator's swap in the same or adjacent block, draining value up to the full swapped amount, matching the severity of the original report (a delegate with limited trust draining the principal's assets).

### Likelihood Explanation
No privileged role is required. Any account that has been granted a `NonTransfer` proxy — a routine, low-trust delegation intended for non-value-moving operations — can exploit this immediately and repeatedly with ordinary signed extrinsics (`pallet_proxy::Call::proxy` wrapping `pallet_asset_conversion::Call::swap_exact_tokens_for_tokens`), with no need for governance, collusion, or exceptional pre-state; the pool for the sandwich/front-run can be set up by the attacker in advance.

### Recommendation
Add `RuntimeCall::AssetConversion(..)` (and any other pallets moving the delegator's assets, following the audit already performed for Asset Hub Westend) to the `NonTransfer` deny-list in `cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs`, mirroring `prdoc/pr_12771.prdoc`. More robustly, convert `NonTransfer` from a deny-list to an allow-list so newly added pallets don't silently become reachable by low-trust proxies in the future.

### Proof of Concept
Reproduction path (integration test against the Asset Hub Rococo runtime, no privileged prerequisites):
1. Delegator `Alice` funds an `AssetConversion` pool for `(Native, AssetX)` and holds a balance of `Native`.
2. Attacker `Bob` (no special role) requests `Alice` to `add_proxy(delegate: Bob, proxy_type: ProxyType::NonTransfer, delay: 0)` — a routine, low-trust delegation.
3. `Bob` observes the pool and pre-positions a sandwich trade.
4. `Bob` calls `Proxy::proxy(real: Alice, force_proxy_type: None, call: AssetConversion::swap_exact_tokens_for_tokens { path: [Native, AssetX], amount_in: <alice_balance>, amount_out_min: 1, send_to: Alice, keep_alive: false })`.
5. `ProxyType::NonTransfer.filter(&call)` returns `true` (per the deny-list shown above, `AssetConversion` is not denied), so the call dispatches with `Alice` as origin.
6. `Alice`'s `Native` is withdrawn and swapped at whatever price the pool state (manipulated by `Bob`'s sandwich) dictates, since `amount_out_min = 1` provides no real protection; `Bob` extracts the difference via his surrounding trades.

This mirrors the fix validated for Asset Hub Westend by the regression tests `non_transfer_proxy_rejects_value_moving_calls` / `value_moving_calls` (which explicitly assert `AssetConversion::swap_exact_tokens_for_tokens` must be denied to `NonTransfer`) [7](#0-6) ; the equivalent assertion is missing and would fail on Asset Hub Rococo's current filter.

### Citations

**File:** substrate/frame/proxy/src/lib.rs (L248-262)
```rust
		pub fn proxy(
			origin: OriginFor<T>,
			real: AccountIdLookupOf<T>,
			force_proxy_type: Option<T::ProxyType>,
			call: Box<<T as Config>::RuntimeCall>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let real = T::Lookup::lookup(real)?;
			let def = Self::find_proxy(&real, &who, force_proxy_type)?;
			ensure!(def.delay.is_zero(), Error::<T>::Unannounced);

			Self::do_proxy(def, real, *call);

			Ok(())
		}
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs (L605-616)
```rust
	fn filter(&self, c: &RuntimeCall) -> bool {
		match self {
			ProxyType::Any => true,
			ProxyType::NonTransfer => !matches!(
				c,
				RuntimeCall::Balances { .. } |
					RuntimeCall::Assets { .. } |
					RuntimeCall::NftFractionalization { .. } |
					RuntimeCall::Nfts { .. } |
					RuntimeCall::Uniques { .. }
			),
			ProxyType::CancelProxy => matches!(
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L527-545)
```rust
		pub fn swap_exact_tokens_for_tokens(
			origin: OriginFor<T>,
			path: Vec<Box<T::AssetKind>>,
			amount_in: T::Balance,
			amount_out_min: T::Balance,
			send_to: T::AccountId,
			keep_alive: bool,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::do_swap_exact_tokens_for_tokens(
				sender,
				path.into_iter().map(|a| *a).collect(),
				amount_in,
				Some(amount_out_min),
				send_to,
				keep_alive,
			)?;
			Ok(())
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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L826-847)
```rust
			// NOTE: This is a deny-list, so it fails open: a pallet added to the runtime is
			// reachable by a `NonTransfer` proxy unless it is listed here. Every call family that
			// can move the delegator's funds or assets must therefore be denied explicitly.
			ProxyType::NonTransfer => !matches!(
				c,
				RuntimeCall::Balances { .. } |
					RuntimeCall::Assets { .. } |
					// The other `pallet-assets` instances transfer value just like `Assets` does.
					RuntimeCall::ForeignAssets { .. } |
					RuntimeCall::PoolAssets { .. } |
					RuntimeCall::NftFractionalization { .. } |
					RuntimeCall::Nfts { .. } |
					RuntimeCall::Uniques { .. } |
					RuntimeCall::Scheduler(..) |
					RuntimeCall::Treasury(..) |
					// Swaps and liquidity provision move the caller's assets.
					RuntimeCall::AssetConversion(..) |
					// Minting and redeeming swap the caller's stablecoins.
					RuntimeCall::Psm(..) |
					// `transfer_assets`, `teleport_assets` and friends move assets to another
					// chain, and `send`/`execute` can express the same thing as raw XCM.
					RuntimeCall::PolkadotXcm(..) |
```

**File:** prdoc/pr_12771.prdoc (L1-22)
```text
title: 'asset-hub-westend: deny value-moving calls to the `NonTransfer` proxy'
doc:
- audience: Runtime User
  description: |-
    On Asset Hub Westend, the `ProxyType::NonTransfer` call filter is a deny-list and so fails
    open: any pallet added to the runtime is reachable by a `NonTransfer` proxy unless it is
    listed explicitly. Several call families that move the delegator's funds or assets were not
    listed, contradicting the documented policy that this proxy type can only execute calls that
    do not transfer funds or assets.

    The following are now denied to a `NonTransfer` proxy:

    - `ForeignAssets` and `PoolAssets` (the other `pallet-assets` instances), which transfer
      value exactly as `Assets` does
    - `AssetConversion`, whose swaps and liquidity operations move the caller's assets
    - `Psm`, whose mint and redeem swap the caller's stablecoins
    - `PolkadotXcm`, whose `transfer_assets`/`teleport_assets` move assets to another chain and
      whose `send`/`execute` can express the same as raw XCM
    - `Revive`, whose contract calls and instantiations carry a `value` to transfer
    - `Indices::transfer` and `Indices::force_transfer`, which repatriate the index's reserved
      deposit to the new owner

```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2591-2668)
```rust
		(
			"AssetConversion::swap_exact_tokens_for_tokens",
			RuntimeCall::AssetConversion(
				pallet_asset_conversion::Call::swap_exact_tokens_for_tokens {
					path: vec![Box::new(some_asset_location()), Box::new(some_asset_location())],
					amount_in: 1,
					amount_out_min: 1,
					send_to: AccountId::from(BOB),
					keep_alive: false,
				},
			),
		),
		(
			"Psm::mint",
			RuntimeCall::Psm(pallet_psm::Call::mint {
				internal_asset: some_asset_location(),
				external_asset: some_asset_location(),
				external_amount: 1,
				max_fee: sp_runtime::Permill::zero(),
			}),
		),
		(
			"PolkadotXcm::transfer_assets",
			RuntimeCall::PolkadotXcm(pallet_xcm::Call::transfer_assets {
				dest: Box::new(xcm::VersionedLocation::from(some_asset_location())),
				beneficiary: Box::new(xcm::VersionedLocation::from(some_asset_location())),
				assets: Box::new(xcm::VersionedAssets::from(XcmAssets::new())),
				fee_asset_item: 0,
				weight_limit: WeightLimit::Unlimited,
			}),
		),
		(
			"Revive::call",
			RuntimeCall::Revive(pallet_revive::Call::call {
				dest: Default::default(),
				value: 1,
				weight_limit: Weight::zero(),
				storage_deposit_limit: 0,
				data: vec![],
			}),
		),
		(
			"Indices::transfer",
			RuntimeCall::Indices(pallet_indices::Call::transfer {
				new: AccountId::from(BOB).into(),
				index: 0,
			}),
		),
	]
}

/// Regression test for <https://github.com/paritytech/polkadot-sdk/issues/12466>.
///
/// `ProxyType::NonTransfer` is documented as permitting "any call that does not transfer funds or
/// assets", but it is implemented as a deny-list and so fails open. `ForeignAssets` and
/// `PoolAssets` transfers were reachable, as were swaps, XCM transfers, contract calls carrying a
/// value, and index transfers (which repatriate the reserved deposit).
#[test]
fn non_transfer_proxy_rejects_value_moving_calls() {
	use asset_hub_westend_runtime::ProxyType;
	use frame_support::traits::InstanceFilter;

	// Collected rather than asserted one by one, so a regression reports every call that slipped
	// through instead of only the first.
	let mut leaked = Vec::new();
	for (name, call) in value_moving_calls() {
		if ProxyType::NonTransfer.filter(&call) {
			leaked.push(name);
		}
		// The call is otherwise well-formed and reachable by a fully permissioned proxy.
		assert!(ProxyType::Any.filter(&call), "Any must permit {name}");
	}

	assert!(
		leaked.is_empty(),
		"NonTransfer must reject calls that move funds or assets, but permitted: {leaked:?}",
	);
}
```
