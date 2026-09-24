I found a promising asymmetry in the Westend relay chain proxy filter. Let me verify the exact enum, `Config` wiring, and the semantics of `paras_registrar::Call::swap` to confirm it's dangerous and reachable.### Title
`NonTransfer` proxy on Westend relay chain can self-escalate to `Registrar::swap` via the `Auction` proxy type - ([File: polkadot/runtime/westend/src/lib.rs])

### Summary
`pallet_proxy::do_proxy` authorizes `add_proxy`/`remove_proxy` calls solely through `ProxyType::is_superset`, before ever consulting `filter` [1](#0-0) . In the Westend relay-chain runtime, `ProxyType::is_superset` declares `NonTransfer` a superset of every other proxy type unconditionally (`(ProxyType::NonTransfer, _) => true`) [2](#0-1) , but `NonTransfer`'s own `filter` explicitly excludes `Registrar::swap` ("Specifically omitting Registrar `swap`") while granting only `register`/`deregister`/`reserve` [3](#0-2) . Meanwhile `ProxyType::Auction`'s filter wildcards the entire `Registrar` pallet (`RuntimeCall::Registrar(..)`), which includes `swap` [4](#0-3) . This is the same class of bug already found and patched for `NonTransfer`/`Governance` on Asset Hub Westend (see `prdoc/pr_12769.prdoc` and the regression test `non_transfer_proxy_is_not_a_superset_of_governance`) [5](#0-4)  — that fix was applied to Asset Hub Westend only, and the equivalent `NonTransfer`/`Auction` asymmetry on the relay-chain runtime (`polkadot/runtime/westend/src/lib.rs`) was left unaddressed.

### Finding Description
This is structurally the same "policy mismatch" class as CVE‑2018‑16398 (Twistlock AuthZ Broker): one filter/pattern grants access based on one matching scheme (path/regex prefix vs. actual dispatched command), and a second, related decision (the superset/subset lattice used for the actual authorization gate) is computed independently and inconsistently, letting the attacker reach a call denied by the intended, narrower filter by first widening their own permission set through the "superset" declaration.

Concretely:
- `pallet_proxy::add_proxy`/`remove_proxy` are gated only by `def.proxy_type.is_superset(proxy_type)` [6](#0-5) ; the actual `filter` is not consulted for these two calls (only for everything else, via `_ => def.proxy_type.filter(c)`).
- `ProxyType::is_superset` for Westend relay chain claims `NonTransfer` dominates every proxy type, including `Auction` [7](#0-6) .
- `ProxyType::Auction::filter` admits any `Registrar` call via the wildcard pattern `RuntimeCall::Registrar(..)`, which includes `paras_registrar::Call::swap` [4](#0-3) .
- `ProxyType::NonTransfer::filter` explicitly excludes `Registrar::swap` from its own grant set, admitting only `register`/`deregister`/`reserve` [8](#0-7) .

So the lattice invariant that the runtime's own comments and tests (for the sibling Asset Hub runtime) treat as mandatory — "a proxy type that declares itself a superset of another must also admit every call that other type admits" [9](#0-8)  — is violated on the relay chain: `NonTransfer` claims to dominate `Auction` while `Auction` can reach `Registrar::swap`, which `NonTransfer` itself cannot reach.

### Impact Explanation
A delegator who grants only a `NonTransfer` proxy (intended to deny anything but a limited, curated call set, explicitly excluding `Registrar::swap`) is exposed to an escalation: the delegate, who is only supposed to be restricted to the `NonTransfer` allow-list, can call `Proxy::add_proxy(delegate_2, ProxyType::Auction, delay)` on behalf of the real account (permitted because `is_superset` says yes), creating a new `Auction` proxy for an account the attacker controls. That `Auction` proxy can then call `Registrar::swap` on behalf of the delegator — a capability the `NonTransfer` proxy was never supposed to have. Because `Registrar::swap` operates on `ParaId` ownership/registration records, this is a swap of parachain registration state under an authorization bypass, not merely an inconvenience, matching the "unauthorized dispatch" bug class this scan prioritizes.

### Likelihood Explanation
Reachability requires only that a delegator has granted (or grants) a `NonTransfer` proxy — a standard, commonly-used, non-privileged proxy type with no special role or governance requirement. The attacker is exactly the proxy delegate: no forged inherent, no validator/collator control, no stolen keys. The two-step call sequence (`add_proxy` then act through the new proxy) uses only ordinary signed extrinsics that are already wired and fee-paying in production.

### Recommendation
Align `ProxyType::is_superset` on the Westend (and any other affected) relay-chain runtime with the actual `filter` semantics, mirroring the fix already applied to Asset Hub Westend in `prdoc/pr_12769.prdoc`: either (a) stop declaring `(ProxyType::NonTransfer, _) => true` unconditionally and instead enumerate only the proxy types whose `filter` sets are fully contained in `NonTransfer`'s (excluding `Auction`, since it can reach `Registrar::swap`), or (b) remove the `Registrar(..)` wildcard from `Auction`'s filter and enumerate the specific non-swap `Registrar` calls it should admit. Add the same lattice-consistency regression test used for Asset Hub Westend (`proxy_type_superset_relation_matches_call_filters`) to the relay-chain runtime test suite to prevent recurrence.

### Proof of Concept
I was not able to execute a runtime integration test in this environment (read-only analysis tools only); the following is the concrete call sequence that a background agent should encode as an integration test using the existing Westend runtime test harness, analogous to `non_transfer_proxy_is_not_a_superset_of_governance` [10](#0-9) :

1. `assert!(ProxyType::Auction.filter(&RuntimeCall::Registrar(paras_registrar::Call::swap { .. })))` — should hold given the wildcard match.
2. `assert!(!ProxyType::NonTransfer.filter(&RuntimeCall::Registrar(paras_registrar::Call::swap { .. })))` — should hold given the explicit exclusion.
3. `assert!(ProxyType::NonTransfer.is_superset(&ProxyType::Auction))` — currently true, which is the bug: it should be `false` per the same invariant enforced for Asset Hub Westend.
4. End-to-end: `Alice` grants `Bob` a `NonTransfer` proxy. `Bob` (signed, no privilege) calls `Proxy::proxy(Bob, Alice, None, Box::new(Proxy::add_proxy(Charlie, ProxyType::Auction, 0)))` — succeeds under current `is_superset` logic. `Charlie` then calls `Proxy::proxy(Charlie, Alice, None, Box::new(Registrar::swap { .. }))` — succeeds, despite `Alice` never having granted access to `Registrar::swap` to any `NonTransfer` delegate.

I did not run this against a live network or claim execution results beyond the code-level filter/superset assertions verified by reading source; the guard function/enum listing (`fn is_superset`, `ProxyType` definitions) is confirmed present exactly as cited above.

### Citations

**File:** substrate/frame/proxy/src/lib.rs (L1002-1021)
```rust
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
```

**File:** polkadot/runtime/westend/src/lib.rs (L971-982)
```rust
				RuntimeCall::Scheduler(..) |
				// Specifically omitting Sudo pallet
				RuntimeCall::Proxy(..) |
				RuntimeCall::Multisig(..) |
				RuntimeCall::Registrar(paras_registrar::Call::register{..}) |
				RuntimeCall::Registrar(paras_registrar::Call::deregister{..}) |
				// Specifically omitting Registrar `swap`
				RuntimeCall::Registrar(paras_registrar::Call::reserve{..}) |
				RuntimeCall::Crowdloan(..) |
				RuntimeCall::Slots(..) |
				RuntimeCall::Auctions(..) // Specifically omitting the entire XCM Pallet
			),
```

**File:** polkadot/runtime/westend/src/lib.rs (L1004-1010)
```rust
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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2486-2492)
```rust
/// `pallet_proxy` authorizes `add_proxy`/`remove_proxy` through `ProxyType::is_superset`, so a
/// proxy type that *declares* itself a superset of another must also *admit* every call that other
/// type admits. Otherwise the "smaller" type is reachable as an escalation: the declared superset
/// can grant itself the subset proxy and thereby gain permissions its own filter denies.
///
/// This checks that property across the whole lattice rather than a single pair, so the class of
/// bug cannot silently reappear on another edge.
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
