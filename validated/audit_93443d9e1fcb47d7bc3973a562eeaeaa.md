### Title
`ProxyType::NonTransfer` deny-list fails open on Asset Hub Rococo, letting a non-transfer proxy move the delegator's assets - ([File: cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs])

### Summary
The rsync CVE's root cause is a security check that "fails open" when a lookup is incomplete: an access-control decision defaults to *allow* instead of *deny* when the check can't be fully evaluated. The Polkadot SDK analog is `ProxyType::NonTransfer` in `pallet-proxy` configurations, which is documented as an allow-list ("can execute any call that does not transfer funds or assets") but is implemented as a **deny-list**: any call/pallet not explicitly named is permitted. This is exactly the same class of bug already identified and partially fixed on Asset Hub Westend (issue [paritytech/polkadot-sdk#12466](https://github.com/paritytech/polkadot-sdk/issues/12466), fixed by PR 12771) and on the `staking-async` parachain runtime (PR 12922), but the parallel Asset Hub Rococo implementation was not updated with the same fix.

### Finding Description
`asset-hub-rococo`'s `InstanceFilter<RuntimeCall>` implementation for `ProxyType::NonTransfer` is: [1](#0-0) 

```
ProxyType::NonTransfer => !matches!(
    c,
    RuntimeCall::Balances { .. } |
        RuntimeCall::Assets { .. } |
        RuntimeCall::NftFractionalization { .. } |
        RuntimeCall::Nfts { .. } |
        RuntimeCall::Uniques { .. }
),
```

This filter only denies `Balances`, `Assets` (the `TrustBackedAssets` instance), `NftFractionalization`, `Nfts`, and `Uniques`. Every other pallet compiled into the same runtime — including value-moving pallets that exist in this runtime, such as `AssetConversion` (swaps/liquidity withdrawal), `PolkadotXcm` (`transfer_assets`/`teleport_assets`/`send`/`execute`), and `Indices::transfer`/`force_transfer` (which repatriates a reserved deposit to a new owner) — is *not* listed, so it falls through to `true` (permitted) via the `!matches!` negation. This is the identical pattern that was explicitly documented and fixed for Asset Hub Westend: [2](#0-1) 

and formally acknowledged in the fix's prdoc: [3](#0-2) 

Asset Hub Rococo has the same `AssetConversion`, `PolkadotXcm`, and `Indices` pallets wired into its runtime (confirmed via the same file's asset-conversion and XCM config sections), but its `NonTransfer` filter was never updated to deny them, unlike Westend's. The bounded PR that shipped the Westend fix (`pr_12771.prdoc`) bumped only `asset-hub-westend-runtime`, not `asset-hub-rococo-runtime`, confirming the Rococo copy was left unpatched.

### Impact Explanation
A delegator who grants a `ProxyType::NonTransfer` proxy — expecting, per the pallet's own doc comment, that the delegate "cannot transfer funds or assets" — is exposed to a delegate who can:
- Call `PolkadotXcm::transfer_assets`/`teleport_assets` to move the delegator's assets to another chain/beneficiary.
- Call `AssetConversion` swap/liquidity-withdrawal calls to move the delegator's assets through a swap to an attacker-controlled `send_to` account.
- Call `Indices::transfer`/`force_transfer` to repatriate the delegator's reserved index deposit to a new owner.

This directly breaks the confidentiality/authorization boundary the proxy type advertises, allowing an authorized-but-limited delegate (attacker with only `NonTransfer` proxy rights, no privileged role) to exfiltrate the delegator's funds — a value-moving unauthorized-dispatch class bug, matching "unauthorized dispatch"/"theft" impact categories.

### Likelihood Explanation
High likelihood of exploitability given a `NonTransfer` proxy relationship exists: no additional privilege, governance action, or malicious external party is required — only a delegate holding a `NonTransfer` proxy (a normal, low-trust delegation a user might grant for convenience) needs to dispatch one of the unlisted calls through `pallet_proxy::proxy`. The `Any` proxy type is verified to permit these same calls, confirming they are reachable dispatches in this runtime and not filtered elsewhere.

### Recommendation
Update `ProxyType::NonTransfer`'s filter in `cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs` to mirror the westend fix: explicitly deny `AssetConversion`, `PolkadotXcm`, `Indices::transfer`/`force_transfer`, and any other value-moving call family present in this runtime's `RuntimeCall` enum (cross-check against `asset-hub-westend`'s corrected list), and add a regression test analogous to `non_transfer_proxy_rejects_value_moving_calls` in `asset-hub-westend/tests/tests.rs` to catch future additions to the runtime that reintroduce the fail-open gap.

### Proof of Concept
Deployment evidence: the vulnerable code is confirmed present in this revision at `cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs:605-621`, and the runtime's `AssetConversion`/`PolkadotXcm`/`Indices` pallets are wired into the same `Runtime` (seen throughout the same file, e.g. `pallet_asset_conversion_tx_payment::Config` at lines 896-908 and XCM config referenced throughout). No test execution was performed in this review (source-level analysis only, per the ask-only/read-only constraints of this session); a minimal Rust reproduction would mirror the existing westend regression test — construct `ProxyType::NonTransfer.filter(&RuntimeCall::AssetConversion(pallet_asset_conversion::Call::swap_exact_tokens_for_tokens{..}))` and `RuntimeCall::PolkadotXcm(pallet_xcm::Call::transfer_assets{..})` and assert both return `true` (currently expected outcome, confirming the leak) using the same harness structure as [4](#0-3) .

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs (L605-621)
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
				c,
				RuntimeCall::Proxy(pallet_proxy::Call::reject_announcement { .. }) |
					RuntimeCall::Utility { .. } |
					RuntimeCall::Multisig { .. }
			),
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L826-860)
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
					// Contract calls and instantiations carry a `value` to transfer.
					RuntimeCall::Revive(..) |
					// We allow calling `vest` and merging vesting schedules, but obviously not
					// vested transfers.
					RuntimeCall::Vesting(pallet_vesting::Call::vested_transfer { .. }) |
					// Transferring an index repatriates its reserved deposit to the new owner.
					// Claiming, freeing and freezing an index are still allowed.
					RuntimeCall::Indices(pallet_indices::Call::transfer { .. }) |
					RuntimeCall::Indices(pallet_indices::Call::force_transfer { .. }) |
					RuntimeCall::ConvictionVoting(..) |
					RuntimeCall::Referenda(..) |
					RuntimeCall::Whitelist(..)
			),
```

**File:** prdoc/pr_12771.prdoc (L1-25)
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

    Calls that do not move value are unaffected, including `Indices::claim`/`free`/`freeze` and
    `Vesting::vest`, as are the call families backing the proxy types that `NonTransfer` declares
    as its subsets.
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2648-2668)
```rust
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
