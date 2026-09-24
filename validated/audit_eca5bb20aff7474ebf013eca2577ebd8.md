### Title
`NonTransfer` proxy on Westend relay chain falsely declares itself a superset of `SudoBalances`, letting a non-transfer delegate grant itself sudo-gated Balances access - ([File: polkadot/runtime/westend/src/lib.rs])

### Summary
`pallet_proxy` gates `add_proxy`/`remove_proxy` solely on `ProxyType::is_superset`, not on `filter` [1](#0-0) . On the Westend relay-chain runtime, `ProxyType::is_superset` has a catch-all arm `(ProxyType::NonTransfer, _) => true`, which makes `NonTransfer` a declared superset of `ProxyType::SudoBalances` [2](#0-1) . But `NonTransfer`'s own `filter` explicitly omits the `Sudo` pallet ("Specifically omitting Sudo pallet"), while `SudoBalances`'s `filter` admits `Sudo(pallet_sudo::Call::sudo{ call: Balances(..) })` and `Utility` [3](#0-2) . This is the exact bug class Parity already fixed once for `NonTransfer`→`Governance` on Asset Hub Westend (GHSA/PR 12769) [4](#0-3) , but the equivalent `NonTransfer`→`SudoBalances` edge on the relay-chain runtime was not covered by that fix and has no lattice-consistency regression test guarding it (unlike Asset Hub Westend's `proxy_type_superset_relation_matches_call_filters` test) [5](#0-4) .

### Finding Description
`pallet_proxy::do_proxy` adds an origin filter before dispatching a proxied call: for `add_proxy`/`remove_proxy` calls it only checks `!def.proxy_type.is_superset(proxy_type)`, and only falls back to `def.proxy_type.filter(c)` for everything else [6](#0-5) . The invariant this design assumes is: "if `A.is_superset(B)` is true, then `A.filter` must admit every call that `B.filter` admits" — otherwise a delegate holding proxy type `A` can grant itself/another account proxy type `B`, and thereby dispatch calls that `A`'s own filter denies (i.e. exactly the RBAC "escalate beyond your own granted permission set" pattern in the report).

On `polkadot/runtime/westend/src/lib.rs`:
- `ProxyType::NonTransfer::filter` denies `Sudo` calls by omission — the code comment reads "// Specifically omitting Sudo pallet" [7](#0-6) .
- `ProxyType::SudoBalances::filter` admits `RuntimeCall::Sudo(pallet_sudo::Call::sudo{ call: x })` when `x` is a `Balances` call, plus `Utility` [8](#0-7) .
- `ProxyType::is_superset` has the default arm `(ProxyType::NonTransfer, _) => true`, which makes `NonTransfer.is_superset(&SudoBalances) == true` since no earlier, more specific arm intercepts that pair [2](#0-1) .

Consequence: a delegate holding a `NonTransfer` proxy for a "real" account can call `Proxy::proxy(real, NonTransfer, Proxy::add_proxy{ delegate: attacker, proxy_type: SudoBalances, delay: 0 })`. `do_proxy`'s origin filter permits this because `is_superset` says yes, even though `NonTransfer`'s own `filter` would reject a direct `Sudo` call. The attacker-controlled `delegate` account then holds a `SudoBalances` proxy over `real`, and can call `Proxy::proxy(real, SudoBalances, Sudo::sudo{ call: Balances::force_transfer{..} })`. Inside `do_proxy` this dispatches with `origin = RawOrigin::Signed(real)` [9](#0-8) ; `pallet_sudo::sudo` only checks that this signed origin equals the stored `Key` account, not that the extrinsic was submitted directly by that key-holder. If `real` happens to be the account holding the `Sudo` `Key`, the escalation succeeds and Balances state can be mutated arbitrarily (mint/force-transfer), i.e. unbacked issuance / theft, purely because a limited (`NonTransfer`) delegate was able to grant itself a broader (`SudoBalances`) proxy type that its own filter denies.

This mirrors the report's invariant violation precisely: a `UserWrite`-equivalent limited role (`NonTransfer`) was able to create a delegate/user with a higher, sudo-adjacent permission (`SudoBalances`) than its own filter allows, due to a missing/insufficient consistency check between `is_superset` and `filter`.

### Impact Explanation
If exploitable, impact is High/Critical: unauthorized dispatch of `Sudo`-gated `Balances` calls (arbitrary mint/force-transfer) constitutes unbacked issuance / theft on the relay chain, matching the report's C:H/I:H/A:H rating for privilege escalation via an under-checked permission grant.

### Likelihood Explanation
Likelihood is constrained by a real precondition: the consequence only materializes if the `real` account that granted the `NonTransfer` proxy is itself the account holding `pallet_sudo::Key`. On Westend this is a small, Parity-controlled account. The mismatch itself (`is_superset` vs `filter`) is a genuine, currently-unguarded logic defect reachable by any ordinary `NonTransfer` delegate with no privileged role, exactly as in the already-fixed `NonTransfer`↔`Governance` sibling bug (PR 12769) — but the practical blast radius on Westend today depends on whether the sudo key account ever grants `NonTransfer` proxies, which I could not verify from the indexed code (genesis/`Key` assignment and any operational proxy grants by that account are outside the available index). I was also unable to fully confirm within the remaining iterations whether an analogous `is_superset`/`filter` mismatch exists on the `substrate/frame/staking-async/runtimes/rc` runtime, which also defines a `SudoBalances` proxy type; that file's `is_superset` implementation was only partially inspected before running out of tool calls.

### Recommendation
Add an explicit arm to `ProxyType::is_superset` on `polkadot/runtime/westend/src/lib.rs` (and audit `substrate/frame/staking-async/runtimes/rc/src/lib.rs` for the same enum) so that `NonTransfer` is not treated as a superset of `SudoBalances` (mirroring the fix already applied for `NonTransfer`/`Governance` in PR 12769) [4](#0-3) . Additionally, port the lattice-consistency regression test `proxy_type_superset_relation_matches_call_filters` from `asset-hub-westend` [5](#0-4)  to the relay-chain runtime(s) so any future `filter`/`is_superset` divergence is caught automatically instead of relying on manual review.

### Proof of Concept
I did not execute a runnable integration test; this is a static code-inspection finding based on directly reading the `filter`/`is_superset` implementations cited above, in the same pattern as the already-merged fix for the sibling `NonTransfer`/`Governance` bug. A concrete PoC would extend `substrate/frame/proxy/src/tests.rs`-style harness (as used for the `Governance` regression test) with: (1) grant `NonTransfer` proxy from a mock "sudo key" account to an attacker account, (2) have the attacker call `Proxy::add_proxy` to grant itself `SudoBalances` on that account, (3) assert the add succeeds (violating intent), (4) have the attacker then call `Sudo::sudo(Balances::force_transfer)` via the `SudoBalances` proxy and assert it dispatches successfully. I was not able to run this within the available iterations; this should be validated in a background session against `polkadot/runtime/westend`'s actual `Key` genesis wiring before filing as confirmed.

### Citations

**File:** substrate/frame/proxy/src/lib.rs (L994-1021)
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
```

**File:** polkadot/runtime/westend/src/lib.rs (L950-993)
```rust
impl InstanceFilter<RuntimeCall> for ProxyType {
	fn filter(&self, c: &RuntimeCall) -> bool {
		match self {
			ProxyType::Any => true,
			ProxyType::NonTransfer => matches!(
				c,
				RuntimeCall::System(..) |
				RuntimeCall::Babe(..) |
				RuntimeCall::Timestamp(..) |
				RuntimeCall::Indices(pallet_indices::Call::claim{..}) |
				RuntimeCall::Indices(pallet_indices::Call::free{..}) |
				RuntimeCall::Indices(pallet_indices::Call::freeze{..}) |
				// Specifically omitting Indices `transfer`, `force_transfer`
				// Specifically omitting the entire Balances pallet
				RuntimeCall::Session(..) |
				RuntimeCall::Grandpa(..) |
				RuntimeCall::Utility(..) |
				RuntimeCall::Identity(..) |
				RuntimeCall::Vesting(pallet_vesting::Call::vest{..}) |
				RuntimeCall::Vesting(pallet_vesting::Call::vest_other{..}) |
				// Specifically omitting Vesting `vested_transfer`, and `force_vested_transfer`
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
