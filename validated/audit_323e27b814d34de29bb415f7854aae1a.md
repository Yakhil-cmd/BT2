No vulnerability found for this question.

**Rationale:** The EVM report's root cause is that `AccessControl.sol` derives role identifiers from `msg.sig` (a 4-byte hash of a function signature) and treats a collision with `ROOT = 0x00000000` as implicit root authorization, combined with a mechanism (`_moduleCall`) that lets new code be added without checking for such collisions.

This pattern has no structural analog in the polkadot-sdk FRAME dispatch model:

- Dispatchable call routing does not derive from a hashed function signature. Each pallet's `Call` enum variant is assigned an explicit, developer-specified `#[pallet::call_index(N)]` (a single `u8`), and the macro that expands `#[pallet::call]` produces `GetCallIndex`/`UnfilteredDispatchable` impls purely from these explicit indices. [1](#0-0) [2](#0-1) 
- Any accidental collision between two call indices within the same pallet is rejected at **compile time** by the procedural macro, not at runtime, so there is no way for an attacker-influenced index to silently collide with a privileged one. [3](#0-2) 
- Root authorization in FRAME is expressed via `OriginFor<T>` / `ensure_root(origin)`, checked against the actual dispatch origin (`frame_system::RawOrigin::Root`), not via any value derived from the call's encoded selector/index. [4](#0-3) 
- The closest conceptually related "permission collision" issue found in this codebase is a *different* bug class: `pallet-proxy`'s `ProxyType::is_superset` lattice, where `NonTransfer` on Asset Hub Westend incorrectly declared itself a superset of `Governance` while its `filter` denied calls `Governance` allowed, letting a `NonTransfer` proxy escalate by adding a `Governance` proxy for itself. [5](#0-4)  This is already fixed and covered by regression tests (`non_transfer_proxy_is_not_a_superset_of_governance`, `proxy_type_superset_relation_matches_call_filters`) and a shipped prdoc. [6](#0-5) [7](#0-6)  Since it is already patched with regression coverage, it does not qualify as a new, reproducible finding.

No other attacker-controlled, unprivileged entry point was found where a runtime-derived "role" value could collide with a privileged constant analogous to `ROOT = 0x00000000` in the EVM report.

### Citations

**File:** substrate/frame/support/procedural/src/pallet/expand/call.rs (L509-522)
```rust
		impl<#type_impl_gen> #frame_support::traits::GetCallIndex for #call_ident<#type_use_gen>
			#where_clause
		{
			fn get_call_index(&self) -> u8 {
				match *self {
					#( #cfg_attrs Self::#fn_name { .. } => #call_index, )*
					Self::__Ignore(_, _) => unreachable!("__PhantomItem cannot be used."),
				}
			}

			fn get_call_indices() -> &'static [u8] {
				&[ #( #cfg_attrs #call_index, )* ]
			}
		}
```

**File:** substrate/frame/support/procedural/src/pallet/parse/call.rs (L401-423)
```rust

				let explicit_call_index = call_index.is_some();

				let final_index = match call_index {
					Some(i) => i,
					None => {
						last_index.map_or(Some(0), |idx| idx.checked_add(1)).ok_or_else(|| {
							let msg = "Call index doesn't fit into u8, index is 256";
							syn::Error::new(method.sig.span(), msg)
						})?
					},
				};
				last_index = Some(final_index);

				if let Some(used_fn) = indices.insert(final_index, method.sig.ident.clone()) {
					let msg = format!(
						"Call indices are conflicting: Both functions {} and {} are at index {}",
						used_fn, method.sig.ident, final_index,
					);
					let mut err = syn::Error::new(used_fn.span(), &msg);
					err.combine(syn::Error::new(method.sig.ident.span(), msg));
					return Err(err);
				}
```

**File:** substrate/frame/support/test/tests/pallet_ui/call_conflicting_indices.stderr (L1-11)
```text
error: Call indices are conflicting: Both functions foo and bar are at index 10
  --> tests/pallet_ui/call_conflicting_indices.rs:32:10
   |
32 |         pub fn foo(origin: OriginFor<T>) -> DispatchResultWithPostInfo {}
   |                ^^^

error: Call indices are conflicting: Both functions foo and bar are at index 10
  --> tests/pallet_ui/call_conflicting_indices.rs:36:10
   |
36 |         pub fn bar(origin: OriginFor<T>) -> DispatchResultWithPostInfo {}
   |                ^^^
```

**File:** substrate/frame/system/src/lib.rs (L831-841)
```rust
		/// Authorize an upgrade to a given `code_hash` for the runtime. The runtime can be supplied
		/// later.
		///
		/// This call requires Root origin.
		#[pallet::call_index(9)]
		#[pallet::weight((T::SystemWeightInfo::authorize_upgrade(), DispatchClass::Operational))]
		pub fn authorize_upgrade(origin: OriginFor<T>, code_hash: T::Hash) -> DispatchResult {
			ensure_root(origin)?;
			Self::do_authorize_upgrade(code_hash, true);
			Ok(())
		}
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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2518-2548)
```rust
/// Regression test for <https://github.com/paritytech/polkadot-sdk/issues/12724>.
///
/// `NonTransfer` used to claim `Governance` as a subset while denying the `Treasury`,
/// `ConvictionVoting`, `Referenda` and `Whitelist` calls that `Governance` admits, which let a
/// `NonTransfer` proxy add a `Governance` proxy and widen its own permissions.
#[test]
fn non_transfer_proxy_is_not_a_superset_of_governance() {
	use asset_hub_westend_runtime::ProxyType;
	use frame_support::traits::InstanceFilter;

	// `NonTransfer` denies every governance call family that `Governance` admits, except `Utility`.
	for call in [
		RuntimeCall::Treasury(pallet_treasury::Call::void_spend { index: 0 }),
		RuntimeCall::ConvictionVoting(pallet_conviction_voting::Call::remove_vote {
			class: None,
			index: 0,
		}),
		RuntimeCall::Referenda(pallet_referenda::Call::refund_decision_deposit { index: 0 }),
		RuntimeCall::Whitelist(pallet_whitelist::Call::remove_whitelisted_call {
			call_hash: Default::default(),
		}),
	] {
		assert!(ProxyType::Governance.filter(&call), "Governance must admit {call:?}");
		assert!(!ProxyType::NonTransfer.filter(&call), "NonTransfer must deny {call:?}");
	}

	// So it must not declare itself a superset of it. This is what stops a `NonTransfer` proxy
	// from granting itself a `Governance` proxy: `pallet_proxy` gates `add_proxy`/`remove_proxy`
	// on `is_superset` before it ever consults `filter`, which by itself does not deny `Proxy`
	// calls.
	assert!(!ProxyType::NonTransfer.is_superset(&ProxyType::Governance));
```

**File:** prdoc/pr_12769.prdoc (L1-19)
```text
title: 'asset-hub-westend: fix `NonTransfer` proxy falsely claiming `Governance` containment'
doc:
- audience: Runtime User
  description: |-
    On Asset Hub Westend, the `NonTransfer` proxy type declared itself a superset of the
    `Governance` proxy type while its call filter denied the `Treasury`, `ConvictionVoting`,
    `Referenda` and `Whitelist` calls that `Governance` admits.

    Because `pallet_proxy` authorizes `add_proxy`/`remove_proxy` through `is_superset`, a
    `NonTransfer` proxy could add a `Governance` proxy for its delegator and thereby reach calls
    that its own filter denies. `NonTransfer` no longer declares `Governance` as a subset, so this
    is rejected.

    Existing `Governance` proxies are unaffected; only the ability of a `NonTransfer` proxy to
    create or remove one changes. The `Collator`, `Staking`, `NominationPools` and
    `StakingOperator` subsets of `NonTransfer` are unchanged.
crates:
- name: asset-hub-westend-runtime
  bump: patch
```
