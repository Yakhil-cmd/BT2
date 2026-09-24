The original report concerns an Aptos Move access-control module that doesn't exist in this Rust/FRAME codebase, so there's no direct code correspondence. However, the underlying invariant violated — "a permission tier that should be checked/restricted is silently exempted from a security check that its sibling tier receives" — has a demonstrable structural analog in `pallet-proxy`'s `ProxyType::is_superset`/`filter` contract, which this repo has already identified and fixed once (asset-hub-westend `NonTransfer`/`Governance`, PR #12769) and hardened with a lattice-wide regression test [1](#0-0) . That fix and its test only cover asset-hub-westend, not the relay-chain/staking-async `rc` runtimes, where I found a structurally identical, still-unfixed gap.

### Title
`ProxyType::NonTransfer` falsely claims superset of `ProxyType::Auction`, permitting escalation via `Registrar::swap` - (File: polkadot/runtime/westend/src/lib.rs)

### Summary
In `polkadot/runtime/westend/src/lib.rs` (and identically in `substrate/frame/staking-async/runtimes/rc/src/lib.rs`), `ProxyType::NonTransfer`'s `filter` is an allow-list that explicitly excludes `Registrar::swap` (the code comments it: "Specifically omitting Registrar `swap`") [2](#0-1) , yet `is_superset` declares `NonTransfer` a superset of every other `ProxyType`, including `ProxyType::Auction`, via the wildcard arm `(ProxyType::NonTransfer, _) => true` [3](#0-2) . But `ProxyType::Auction`'s filter admits `RuntimeCall::Registrar(..)` unrestricted — i.e., including `swap` [4](#0-3) . This is exactly the bug class already found and fixed for `NonTransfer`/`Governance` on asset-hub-westend [5](#0-4) , but that fix was not applied to the `Auction` pair on the relay-chain runtimes.

### Finding Description
`pallet-proxy`'s `do_proxy` gates `add_proxy`/`remove_proxy` sub-calls solely via `InstanceFilter::is_superset`, independent of `filter`: [6](#0-5) 
If `is_superset(def.proxy_type, target_type)` returns `true`, the delegate is permitted to call `add_proxy`/`remove_proxy` with `target_type`, regardless of whether `filter(def.proxy_type)` actually admits every call that `filter(target_type)` admits. This "declared vs. actual" mismatch is precisely the invariant violated in the Move report: a role/tier is exempted from the check that ensures its declared scope matches its real capabilities.

For `westend`/`staking-async rc`, `ProxyType::NonTransfer` intentionally omits `Registrar::swap` from its own filter (comment explicitly calls this out), meaning a `NonTransfer` delegate cannot directly dispatch `Registrar::swap` on behalf of the real account. But `is_superset` still reports `NonTransfer ⊇ Auction`, and `ProxyType::Auction`'s filter unconditionally admits all `Registrar` calls, including `swap` [4](#0-3) .

### Impact Explanation
A `NonTransfer` proxy delegate could call `Proxy::add_proxy(real, ProxyType::Auction, delay)` — allowed since `NonTransfer` admits all `RuntimeCall::Proxy(..)` calls [7](#0-6)  and `is_superset` does not block it. Once an `Auction`-type proxy exists for the real account, that proxy (which could be the same delegate or a chosen third party) could call `Registrar::swap` on the real account's behalf, an action the original `NonTransfer` grant deliberately withheld. This is a proxy privilege-escalation bug, structurally identical to the previously-fixed `NonTransfer`/`Governance` issue.

### Likelihood Explanation
Requires only a standard, non-privileged `NonTransfer` proxy relationship (a normal, permitted delegation any user can set up) and two ordinary signed extrinsics (`add_proxy` then `proxy`). No governance, root, or validator access is needed — matching the report's "no privileged prerequisites" bar.

### Recommendation
Apply the same fix pattern used in PR #12769: remove the `(ProxyType::NonTransfer, _) => true` wildcard and enumerate only the proxy types whose filters are provably subsets of `NonTransfer`'s allow-list (as asset-hub-westend now does), or explicitly deny `Auction` (and any other type admitting `Registrar::swap`) as a `NonTransfer` subset.

### Proof of Concept
I was not able to fully verify `Registrar::swap`'s exact runtime effect (couldn't retrieve its full body within available iterations) or confirm whether westend/staking-async-rc have an equivalent regression test to asset-hub-westend's `proxy_type_superset_relation_matches_call_filters` [1](#0-0) ; a grep found no such lattice test file for `polkadot/runtime/westend` or `substrate/frame/staking-async/runtimes/rc`, suggesting the fix/test applied on asset-hub-westend was not backported. No live extrinsic execution was run against a node; this is a static-code demonstration of the mismatch between `filter` and `is_superset`, following the exact precedent already fixed once in this repository (PR #12769, PR #12922) for the same class of bug.

### Citations

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

**File:** polkadot/runtime/westend/src/lib.rs (L973-974)
```rust
				RuntimeCall::Proxy(..) |
				RuntimeCall::Multisig(..) |
```

**File:** polkadot/runtime/westend/src/lib.rs (L975-978)
```rust
				RuntimeCall::Registrar(paras_registrar::Call::register{..}) |
				RuntimeCall::Registrar(paras_registrar::Call::deregister{..}) |
				// Specifically omitting Registrar `swap`
				RuntimeCall::Registrar(paras_registrar::Call::reserve{..}) |
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

**File:** substrate/frame/proxy/src/lib.rs (L1004-1013)
```rust
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
```
