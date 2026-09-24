### Title
`NonTransfer` proxy on Polkadot's relay-chain runtimes falsely declares itself a superset of `Auction`, letting it self-escalate into the `Registrar::swap` call it explicitly excludes - ([File: polkadot/runtime/westend/src/lib.rs])

### Summary
`pallet_proxy` authorizes `add_proxy`/`remove_proxy` purely via `InstanceFilter::is_superset`, not via `InstanceFilter::filter` [1](#0-0) . On the Westend relay-chain runtime (and the identical code path in `substrate/frame/staking-async/runtimes/rc/src/lib.rs`), `ProxyType::NonTransfer` is declared a blanket superset of every other `ProxyType` [2](#0-1) , including `ProxyType::Auction`. But `NonTransfer`'s call filter deliberately excludes `Registrar::swap` (comment: "Specifically omitting Registrar `swap`") while `Auction`'s filter admits the entire `Registrar` call family unconditionally [3](#0-2) . This is the exact same bug class that was already found and fixed once in this codebase for `NonTransfer`/`Governance` on Asset Hub Westend (regression test `non_transfer_proxy_is_not_a_superset_of_governance`, prdoc `pr_12769.prdoc`, upstream issue #12724) [4](#0-3)  — but it recurs unpatched here for a different pair of proxy types.

### Finding Description
`pallet_proxy::do_proxy` wraps the delegate's call in an origin filter that specifically blocks a proxy from adding/removing a proxy definition with *more* permissions than its own, using `def.proxy_type.is_superset(proxy_type)` as the gate — it never re-checks `filter` for this purpose [5](#0-4) . The invariant this depends on is that when type A declares `is_superset(B) == true`, A's `filter` must admit every call that B's `filter` admits — otherwise A can grant itself a B proxy and dispatch calls its own filter denies.

On `polkadot/runtime/westend`:
- `is_superset` maps `(ProxyType::NonTransfer, _) => true` for any other variant except `Any` [2](#0-1) .
- `NonTransfer`'s filter admits only `Registrar::register`, `Registrar::deregister`, `Registrar::reserve` — the code comment explicitly states `swap` is omitted [6](#0-5) .
- `Auction`'s filter admits `RuntimeCall::Registrar(..)` unconditionally, i.e. every Registrar call including `swap` [7](#0-6) .

Since `NonTransfer.is_superset(Auction) == true`, a `NonTransfer` proxy is permitted by `pallet_proxy` to call `add_proxy(delegate, Auction, ..)` on behalf of the real account. That new `Auction` proxy delegate can then call `proxy(real, Some(Auction), Registrar::swap{..})`, which `Auction`'s filter admits. The `NonTransfer` delegate has thereby dispatched `Registrar::swap` on behalf of the real account — a call its own `NonTransfer` grant was explicitly designed to exclude. The identical `ProxyType` code (including the same comment and the same `(NonTransfer, _) => true` blanket rule) is duplicated in `substrate/frame/staking-async/runtimes/rc/src/lib.rs` [8](#0-7) .

### Impact Explanation
This does not let the delegate exceed what the *real* account itself could already do (matching the CVE's own caveat that scope bypass cannot exceed the owner's own permissions) — but it breaks the scoping contract of a `NonTransfer` proxy grant: an account owner who deliberately withheld `Registrar::swap` authority from a delegate by granting `NonTransfer` (rather than `Any` or `Auction`) can have that authority silently reinstated by the delegate itself, without the owner's consent, via a two-step `add_proxy` + `proxy` sequence. `Registrar::swap` affects parachain slot/ID assignment for the real account's paras, which is a meaningful capability to leak from a supposedly-restricted delegate.

### Likelihood Explanation
High, in the sense that the mismatch is deterministic and requires no privileged role: any account that has granted a `NonTransfer` proxy to another account is exposed, and the delegate needs only two ordinary signed extrinsics (`Proxy::add_proxy`, `Proxy::proxy`) with normal transaction fees. The precondition (delegator having previously registered a para and granted a `NonTransfer` proxy) is a documented, expected relay-chain configuration, not an attacker-controlled or privileged prerequisite.

### Recommendation
Fix `ProxyType::is_superset` on `polkadot/runtime/westend` (and the duplicated `substrate/frame/staking-async/runtimes/rc` runtime) so `NonTransfer` is not claimed as a superset of `Auction` (or any other type it does not fully dominate), mirroring the fix already applied for `NonTransfer`/`Governance` in `pr_12769.prdoc`. Ideally, add the same kind of lattice regression test used on Asset Hub Westend (`proxy_type_superset_relation_matches_call_filters`) to these runtimes to prevent recurrence [9](#0-8) .

### Proof of Concept
I was not able to complete a full executed integration-test reproduction within the available investigation budget. What is verified directly from source:
- The `is_superset`/`filter` mismatch itself, confirmed by reading the exact `ProxyType::filter` and `ProxyType::is_superset` implementations in `polkadot/runtime/westend/src/lib.rs` lines 950–1031 and the duplicate in `substrate/frame/staking-async/runtimes/rc/src/lib.rs` lines 1323–1419.
- That `pallet_proxy::do_proxy` gates `add_proxy`/`remove_proxy` solely on `is_superset`, not `filter`, in `substrate/frame/proxy/src/lib.rs` lines 994–1023.
- That this exact class of bug (a proxy type falsely declaring itself a superset, enabling self-escalation) was previously found and fixed for a different type pair (`NonTransfer`/`Governance`) on Asset Hub Westend, evidenced by the still-present regression test and `prdoc/pr_12769.prdoc`.

Not yet confirmed (would require deeper reading of `polkadot_runtime_common::paras_registrar::Pallet::swap` and running an actual proxy-pallet integration test against the Westend runtime, which I could not complete before running out of tool-call budget): the exact origin/authorization requirements inside `swap` itself (e.g., whether it requires being the manager of both paras, or additional governance approval), and an executed test run demonstrating the end-to-end `add_proxy` → `proxy(Auction, swap)` sequence succeeding on-chain. I flag this explicitly rather than asserting an executed PoC result.

### Citations

**File:** substrate/frame/proxy/src/lib.rs (L994-1023)
```rust
	fn do_proxy(
		def: ProxyDefinition<T::AccountId, T::ProxyType, BlockNumberFor<T>>,
		real: T::AccountId,
		call: <T as Config>::RuntimeCall,
	) {
		use frame::traits::{InstanceFilter as _, OriginTrait as _};
		// This is a freshly authenticated new account, the origin restrictions doesn't apply.
		let mut origin: T::RuntimeOrigin = frame_system::RawOrigin::Signed(real).into();
		origin.add_filter(move |c: &<T as frame_system::Config>::RuntimeCall| {
			let c = <T as Config>::RuntimeCall::from_ref(c);
			// We make sure the proxy call does access this pallet to change modify proxies.
			match c.is_sub_type() {
				// Proxy call cannot add or remove a proxy with more permissions than it already
				// has.
				Some(Call::add_proxy { ref proxy_type, .. }) |
				Some(Call::remove_proxy { ref proxy_type, .. })
					if !def.proxy_type.is_superset(proxy_type) =>
				{
					false
				},
				// Proxy call cannot remove all proxies or kill pure proxies unless it has full
				// permissions.
				Some(Call::remove_proxies { .. }) | Some(Call::kill_pure { .. })
					if def.proxy_type != T::ProxyType::default() =>
				{
					false
				},
				_ => def.proxy_type.filter(c),
			}
		});
```

**File:** polkadot/runtime/westend/src/lib.rs (L975-1010)
```rust
				RuntimeCall::Registrar(paras_registrar::Call::register{..}) |
				RuntimeCall::Registrar(paras_registrar::Call::deregister{..}) |
				// Specifically omitting Registrar `swap`
				RuntimeCall::Registrar(paras_registrar::Call::reserve{..}) |
				RuntimeCall::Crowdloan(..) |
				RuntimeCall::Slots(..) |
				RuntimeCall::Auctions(..) // Specifically omitting the entire XCM Pallet
			),
			// Staking and session key management have moved to Asset Hub; this proxy is
			// no longer needed, but we keep it so that on-chain proxy entries still decode.
			ProxyType::Staking => false,
			ProxyType::NominationPools => false,
			ProxyType::SudoBalances => match c {
				RuntimeCall::Sudo(pallet_sudo::Call::sudo { call: ref x }) => {
					matches!(x.as_ref(), &RuntimeCall::Balances(..))
				},
				RuntimeCall::Utility(..) => true,
				_ => false,
			},
			// Governance has moved to AssetHub post-AHM; no calls to proxy.
			ProxyType::Governance => false,
			ProxyType::IdentityJudgement => matches!(
				c,
				RuntimeCall::Identity(pallet_identity::Call::provide_judgement { .. }) |
					RuntimeCall::Utility(..)
			),
			ProxyType::CancelProxy => {
				matches!(c, RuntimeCall::Proxy(pallet_proxy::Call::reject_announcement { .. }))
			},
			ProxyType::Auction => matches!(
				c,
				RuntimeCall::Auctions(..) |
					RuntimeCall::Crowdloan(..) |
					RuntimeCall::Registrar(..) |
					RuntimeCall::Slots(..)
			),
```

**File:** polkadot/runtime/westend/src/lib.rs (L1022-1030)
```rust
	fn is_superset(&self, o: &Self) -> bool {
		match (self, o) {
			(x, y) if x == y => true,
			(ProxyType::Any, _) => true,
			(_, ProxyType::Any) => false,
			(ProxyType::NonTransfer, _) => true,
			_ => false,
		}
	}
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2493-2516)
```rust
#[test]
fn proxy_type_superset_relation_matches_call_filters() {
	use frame_support::traits::InstanceFilter;

	let calls = representative_proxy_calls();

	for superset in all_proxy_types() {
		for subset in all_proxy_types() {
			if !superset.is_superset(&subset) {
				continue;
			}

			for call in calls.iter() {
				if subset.filter(call) {
					assert!(
						superset.filter(call),
						"lattice violated: {superset:?} declares itself a superset of {subset:?}, \
						 but rejects {call:?} which {subset:?} admits",
					);
				}
			}
		}
	}
}
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

**File:** substrate/frame/staking-async/runtimes/rc/src/lib.rs (L1358-1417)
```rust
				// Specifically omitting Registrar `swap`
				RuntimeCall::Registrar(paras_registrar::Call::reserve{..}) |
				RuntimeCall::Crowdloan(..) |
				RuntimeCall::Slots(..) |
				RuntimeCall::Auctions(..)
			),
			ProxyType::Staking => {
				matches!(c, RuntimeCall::Session(..) | RuntimeCall::Utility(..))
			},
			ProxyType::NominationPools => {
				matches!(c,| RuntimeCall::Utility(..))
			},
			ProxyType::SudoBalances => match c {
				RuntimeCall::Sudo(pallet_sudo::Call::sudo { call: ref x }) => {
					matches!(x.as_ref(), &RuntimeCall::Balances(..))
				},
				RuntimeCall::Utility(..) => true,
				_ => false,
			},
			ProxyType::Governance => matches!(
				c,
				// OpenGov calls
				RuntimeCall::ConvictionVoting(..) |
					RuntimeCall::Referenda(..) |
					RuntimeCall::Whitelist(..)
			),
			ProxyType::IdentityJudgement => matches!(
				c,
				RuntimeCall::Identity(pallet_identity::Call::provide_judgement { .. }) |
					RuntimeCall::Utility(..)
			),
			ProxyType::CancelProxy => {
				matches!(c, RuntimeCall::Proxy(pallet_proxy::Call::reject_announcement { .. }))
			},
			ProxyType::Auction => matches!(
				c,
				RuntimeCall::Auctions(..) |
					RuntimeCall::Crowdloan(..) |
					RuntimeCall::Registrar(..) |
					RuntimeCall::Slots(..)
			),
			ProxyType::ParaRegistration => matches!(
				c,
				RuntimeCall::Registrar(paras_registrar::Call::reserve { .. }) |
					RuntimeCall::Registrar(paras_registrar::Call::register { .. }) |
					RuntimeCall::Utility(pallet_utility::Call::batch { .. }) |
					RuntimeCall::Utility(pallet_utility::Call::batch_all { .. }) |
					RuntimeCall::Utility(pallet_utility::Call::force_batch { .. }) |
					RuntimeCall::Proxy(pallet_proxy::Call::remove_proxy { .. })
			),
		}
	}
	fn is_superset(&self, o: &Self) -> bool {
		match (self, o) {
			(x, y) if x == y => true,
			(ProxyType::Any, _) => true,
			(_, ProxyType::Any) => false,
			(ProxyType::NonTransfer, _) => true,
			_ => false,
		}
```
