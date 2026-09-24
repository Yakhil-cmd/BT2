### Title
`ProxyType::NonTransfer` on the Polkadot/Rococo relay chain falsely declares itself a superset of `Auction` (and `OnDemandOrdering`), letting a restricted proxy escalate to calls its own filter explicitly denies - (File: `polkadot/runtime/rococo/src/lib.rs`)

### Summary
`pallet_proxy` gates `add_proxy`/`remove_proxy` solely on `InstanceFilter::is_superset`, not on `filter` [1](#0-0) . On `polkadot/runtime/rococo`, `ProxyType::is_superset` contains a blanket rule `(ProxyType::NonTransfer, _) => true` [2](#0-1) , meaning a `NonTransfer` proxy is trusted to create/remove *any* other proxy type for its delegator, including `Auction`. But `NonTransfer`'s `filter` explicitly documents omitting `Registrar::swap` [3](#0-2) , while `ProxyType::Auction`'s filter admits the entire `Registrar` pallet including `swap` [4](#0-3) . A `NonTransfer` delegate can therefore add itself an `Auction` proxy and reach `Registrar::swap`, a call its own restricted policy was designed to deny. The same blanket rule also lets `NonTransfer` grant an `OnDemandOrdering` proxy, whose filter admits `OnDemandAssignmentProvider(..)` [5](#0-4) , a pallet `NonTransfer`'s own filter never mentions/admits.

This is the identical bug class already found and patched for `asset-hub-westend`'s `NonTransfer`/`Governance` pair (`prdoc/pr_12769.prdoc` [6](#0-5) , fix visible at `cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs:1002-1013` [7](#0-6) ), but it was never fixed on the Polkadot/Rococo relay chain runtime itself, which still uses the old unconditional `(NonTransfer, _) => true` rule.

### Finding Description
`pallet_proxy::do_proxy` authorizes a proxied `add_proxy`/`remove_proxy` call purely via `def.proxy_type.is_superset(proxy_type)`, never re-checking `filter` for the target type [8](#0-7) . The invariant that must hold for this design to be sound is: *if `A.is_superset(B) == true`, then every call `A.filter` denies must also be denied by `B.filter`* (i.e. `B`'s permissions must be contained in `A`'s). This exact invariant is documented and enforced elsewhere in the same codebase — e.g. the `asset-hub-westend` regression test `proxy_type_superset_relation_matches_call_filters` [9](#0-8)  and the fix comment explaining why `NonTransfer` must not claim `Governance` as a subset [7](#0-6) .

`polkadot/runtime/rococo`'s `ProxyType::is_superset` violates this invariant for two pairs:
- `NonTransfer` vs `Auction`: `NonTransfer.filter` explicitly omits `Registrar::swap` [3](#0-2) , but `Auction.filter` admits the full `Registrar` pallet [4](#0-3) , and `is_superset` still returns `true` for `(NonTransfer, Auction)`.
- `NonTransfer` vs `OnDemandOrdering`: `NonTransfer.filter` never lists `OnDemandAssignmentProvider` [10](#0-9) , but `OnDemandOrdering.filter` admits it fully [5](#0-4) .

This is directly analogous to the MinIO issue's root cause: a check meant to gate "own-account" sub-object creation (`is_superset`, analogous to MinIO's `DenyOnly` check) is satisfied without verifying the new object's *effective permission set* is actually contained in the caller's restricted policy (`filter`, analogous to MinIO's session policy). The result in both cases: a restricted principal creates a new credential/proxy for itself that carries more privilege than its own policy grants.

### Impact Explanation
A holder of only a `NonTransfer` proxy — a role Rococo documentation and the code itself treat as explicitly barred from fund/asset-moving and select "dangerous" operations like `Registrar::swap` — can self-escalate to an `Auction` proxy and invoke `Registrar::swap`, a call it was never intended to reach. `Registrar::swap` swaps para ID registrations/lease positions between two parachain slots, letting a party with lease-holder standing on one side of a swap manipulate slot ownership; reaching it through a supposedly-restricted proxy breaks the confidentiality/integrity guarantee the `NonTransfer` proxy type is documented to provide. This is a genuine authorization-bypass/privilege-escalation bug in a live relay-chain runtime (Rococo), matching CWE-863 (Incorrect Authorization) as in the referenced advisory.

### Likelihood Explanation
Likelihood is High for any account that has already been granted (by itself or a delegator) a `NonTransfer` proxy — a very commonly used, "safe-by-design" proxy type. No privileged role, governance action, or stolen key is required: the attack is a plain signed `Proxy::add_proxy` extrinsic from an account already holding a `NonTransfer` delegation, followed by a `Proxy::proxy` call routed through the newly created `Auction` (or `OnDemandOrdering`) proxy. Both steps are ordinary, fee-paying signed extrinsics through the real, already-wired `pallet_proxy` entry point.

### Recommendation
Apply the same fix pattern already used for `asset-hub-westend` (`prdoc/pr_12769.prdoc`) to `polkadot/runtime/rococo::ProxyType::is_superset`: replace the blanket `(ProxyType::NonTransfer, _) => true` with an explicit, filter-verified list of subset types (only those whose `filter` output is provably contained in `NonTransfer`'s), excluding `Auction` and `OnDemandOrdering`. Add a lattice-consistency test analogous to `proxy_type_superset_relation_matches_call_filters` for the relay-chain runtime to prevent regressions.

### Proof of Concept
Reasoning-level PoC (no test executed; flagged as such):
1. Delegator `D` grants delegate `X` a `ProxyType::NonTransfer` proxy via `Proxy::add_proxy(X, NonTransfer, 0)`.
2. `X` calls `Proxy::proxy(D, None, Box::new(Proxy::add_proxy(X, Auction, 0)))`. Inside `pallet_proxy::do_proxy`, the origin filter checks `def.proxy_type.is_superset(&Auction)` i.e. `NonTransfer.is_superset(&Auction)`, which returns `true` per `polkadot/runtime/rococo/src/lib.rs:1005` [2](#0-1)  — the add succeeds, granting `X` an `Auction` proxy over `D`.
3. `X` now calls `Proxy::proxy(D, None, Box::new(Registrar::swap { .. }))`. The active proxy definition is `Auction`, whose `filter` matches `RuntimeCall::Registrar { .. }` unconditionally [4](#0-3) , so the call is dispatched — even though the original `NonTransfer` grant explicitly excludes `Registrar::swap` by comment [3](#0-2) .

Expected state if the invariant held: step 2 should fail with `CallFiltered`/be rejected because `Auction` is not truly a subset of `NonTransfer`. Actual state per source inspection: step 2 succeeds because `is_superset` is unconditionally `true` for `NonTransfer`. This was verified by static code review of `polkadot/runtime/rococo/src/lib.rs` and cross-referenced against the already-patched, structurally identical `asset-hub-westend` case; no live/integration test was executed against a running chain, and this should be confirmed with a `pallet_proxy` integration test in the Rococo runtime crate before filing.

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

**File:** polkadot/runtime/rococo/src/lib.rs (L922-967)
```rust
			ProxyType::NonTransfer => matches!(
				c,
				RuntimeCall::System(..) |
				RuntimeCall::Babe(..) |
				RuntimeCall::Timestamp(..) |
				RuntimeCall::Indices(pallet_indices::Call::claim {..}) |
				RuntimeCall::Indices(pallet_indices::Call::free {..}) |
				RuntimeCall::Indices(pallet_indices::Call::freeze {..}) |
				// Specifically omitting Indices `transfer`, `force_transfer`
				// Specifically omitting the entire Balances pallet
				RuntimeCall::Session(..) |
				RuntimeCall::Grandpa(..) |
				RuntimeCall::Treasury(..) |
				RuntimeCall::Bounties(..) |
				RuntimeCall::ChildBounties(..) |
				RuntimeCall::ConvictionVoting(..) |
				RuntimeCall::Referenda(..) |
				RuntimeCall::FellowshipCollective(..) |
				RuntimeCall::FellowshipReferenda(..) |
				RuntimeCall::Whitelist(..) |
				RuntimeCall::Claims(..) |
				RuntimeCall::Utility(..) |
				RuntimeCall::Identity(..) |
				RuntimeCall::Society(..) |
				RuntimeCall::Recovery(pallet_recovery::Call::set_friend_groups {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::initiate_attempt {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::approve_attempt {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::finish_attempt {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::cancel_attempt {..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::slash_attempt {..}) |
				// Specifically omitting Recovery `control_inherited_account`
				RuntimeCall::Vesting(pallet_vesting::Call::vest {..}) |
				RuntimeCall::Vesting(pallet_vesting::Call::vest_other {..}) |
				// Specifically omitting Vesting `vested_transfer`, and `force_vested_transfer`
				RuntimeCall::Scheduler(..) |
				RuntimeCall::Proxy(..) |
				RuntimeCall::Multisig(..) |
				RuntimeCall::Nis(..) |
				RuntimeCall::Registrar(paras_registrar::Call::register {..}) |
				RuntimeCall::Registrar(paras_registrar::Call::deregister {..}) |
				// Specifically omitting Registrar `swap`
				RuntimeCall::Registrar(paras_registrar::Call::reserve {..}) |
				RuntimeCall::Crowdloan(..) |
				RuntimeCall::Slots(..) |
				RuntimeCall::Auctions(..) // Specifically omitting the entire XCM Pallet
			),
```

**File:** polkadot/runtime/rococo/src/lib.rs (L988-995)
```rust
			ProxyType::Auction => matches!(
				c,
				RuntimeCall::Auctions { .. } |
					RuntimeCall::Crowdloan { .. } |
					RuntimeCall::Registrar { .. } |
					RuntimeCall::Multisig(..) |
					RuntimeCall::Slots { .. }
			),
```

**File:** polkadot/runtime/rococo/src/lib.rs (L997-997)
```rust
			ProxyType::OnDemandOrdering => matches!(c, RuntimeCall::OnDemandAssignmentProvider(..)),
```

**File:** polkadot/runtime/rococo/src/lib.rs (L1000-1008)
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

**File:** prdoc/pr_12769.prdoc (L1-16)
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
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L1002-1013)
```rust
			// NOTE: `Governance` is deliberately *not* listed here. `NonTransfer` denies the
			// `Treasury`, `ConvictionVoting`, `Referenda` and `Whitelist` calls that `Governance`
			// admits, so it is not a superset of it. Claiming otherwise would let a `NonTransfer`
			// proxy grant itself a `Governance` proxy and widen its own permissions, since
			// `pallet_proxy` authorizes `add_proxy`/`remove_proxy` through `is_superset`.
			(
				ProxyType::NonTransfer,
				ProxyType::Collator |
				ProxyType::Staking |
				ProxyType::NominationPools |
				ProxyType::StakingOperator,
			) => true,
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2486-2516)
```rust
/// `pallet_proxy` authorizes `add_proxy`/`remove_proxy` through `ProxyType::is_superset`, so a
/// proxy type that *declares* itself a superset of another must also *admit* every call that other
/// type admits. Otherwise the "smaller" type is reachable as an escalation: the declared superset
/// can grant itself the subset proxy and thereby gain permissions its own filter denies.
///
/// This checks that property across the whole lattice rather than a single pair, so the class of
/// bug cannot silently reappear on another edge.
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
