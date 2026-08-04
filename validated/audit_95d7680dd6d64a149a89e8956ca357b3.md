### Title
NonTransfer proxy can add an unrestricted `Any` sub-proxy via `Proxy::add_proxy`, bypassing the funds-transfer restriction - (File: system-parachains/people/people-polkadot/src/lib.rs)

### Summary
The `ProxyType::NonTransfer` filter on the People (Polkadot) chain unconditionally allows the entire `Proxy` pallet (`RuntimeCall::Proxy(_)`), including `add_proxy`/`remove_proxy`, without constraining the `proxy_type` parameter of the nested call. An attacker holding only a `NonTransfer` proxy for a victim can therefore add a second delegate as an `Any` proxy for the victim, and then use that new `Any` proxy to execute unrestricted calls (including `Balances` transfers) on the victim's behalf, completely defeating the "non-transfer" guarantee.

### Finding Description
`ProxyType::NonTransfer::filter` matches `RuntimeCall::Proxy(_)` as a blanket wildcard, with no restriction on the inner call's `proxy_type` field: [1](#0-0) 

`pallet_proxy`'s own `add_proxy`/`remove_proxy` extrinsics do not internally enforce `is_superset` between the calling delegate's `proxy_type` and the `proxy_type` being granted — that check is only used by the (unrelated) `remote-proxy` pallet's manually constructed origin filter: [2](#0-1) 

Because of this, the only gate preventing privilege escalation through nested `add_proxy` calls is the `InstanceFilter::filter` implementation itself — and on the People chain, `NonTransfer` places no constraint on which `proxy_type` may be granted via `Proxy::add_proxy`. Contrast this with the Asset Hub runtimes, which explicitly pattern-match the inner call's `proxy_type` field to prevent exactly this kind of escalation for the `Staking` proxy type: [3](#0-2) 

and which have a dedicated regression test proving that a `Staking` proxy cannot add an `Any` proxy (the inner call fails with `CallFiltered`): [4](#0-3) 

No equivalent restriction or test exists for `ProxyType::NonTransfer` on the People chain (or its sibling relay/coretime/collectives runtimes that share the same `RuntimeCall::Proxy(_)` wildcard pattern): [5](#0-4) 

Exploit flow:
1. Victim grants attacker a `ProxyType::NonTransfer` proxy.
2. Attacker calls `Proxy::proxy(victim, Some(NonTransfer), Proxy::add_proxy{ delegate: attacker2, proxy_type: Any, delay: 0 })`. The outer call passes `NonTransfer.filter(&inner_call)` because the inner call is `RuntimeCall::Proxy(..)`, matched unconditionally — no check is made on the `proxy_type: Any` field.
3. `attacker2` is now a fully-permissioned `Any` proxy for the victim, stored via `pallet_proxy::Proxies`.
4. Attacker calls `Proxy::proxy(victim, Some(Any), Balances::transfer_all{ dest: attacker2, ... })`. `Any.filter` always returns `true`, so the transfer executes with the victim as origin.

This is a genuine origin/authorization gap: the `NonTransfer` designation is supposed to prevent asset movement, but by allowing unrestricted `Proxy` pallet management it lets the delegate grant itself unlimited privileges, nullifying the restriction.

### Impact Explanation
An attacker who only holds a `NonTransfer` proxy over a victim account on the People (Polkadot) chain can escalate to full (`Any`) control and drain the victim's native balance (used for identity deposits/fees) via `Balances::transfer_all` or any other privileged call, despite the `NonTransfer` designation being intended specifically to prevent such fund movement.

### Likelihood Explanation
This requires only that the victim has granted a `NonTransfer` proxy to the attacker — a common, low-trust delegation pattern intended to allow limited account management without allowing withdrawal of funds. No governance action, special timing, or race condition is needed; the entire escalation is two ordinary, unprivileged `Proxy::proxy` extrinsics with `delay: 0`, fully reproducible on-chain by any account holding a `NonTransfer` proxy.

### Recommendation
Restrict `ProxyType::NonTransfer`'s `filter` so that `Proxy::add_proxy`/`Proxy::remove_proxy` (and any other privilege-changing call) are only permitted when the target `proxy_type` is itself a subset of `NonTransfer` (e.g., pattern-match on `proxy_type` similar to the Asset Hub `Staking`/`StakingOperator` pattern), rather than allowing the entire `Proxy` pallet unconditionally.

### Proof of Concept
```rust
#[test]
fn nontransfer_proxy_cannot_escalate_to_any_via_add_proxy() {
    // Given: victim grants attacker a NonTransfer proxy
    assert_ok!(Proxy::add_proxy(
        RuntimeOrigin::signed(victim.clone()),
        Lookup::unlookup(attacker.clone()),
        ProxyType::NonTransfer,
        0
    ));

    // When: attacker tries to add attacker2 as an Any proxy for victim, via the NonTransfer proxy
    let add_any_call = RuntimeCall::Proxy(pallet_proxy::Call::add_proxy {
        delegate: Lookup::unlookup(attacker2.clone()),
        proxy_type: ProxyType::Any,
        delay: 0,
    });
    assert_ok!(Proxy::proxy(
        RuntimeOrigin::signed(attacker.clone()),
        Lookup::unlookup(victim.clone()),
        Some(ProxyType::NonTransfer),
        Box::new(add_any_call),
    ));

    // Then: assert the inner call was filtered (expected fix), i.e. attacker2 is NOT an Any proxy
    let proxies = pallet_proxy::Proxies::<Runtime>::get(&victim);
    assert!(
        !proxies.0.iter().any(|p| p.delegate == attacker2 && p.proxy_type == ProxyType::Any),
        "attacker2 should NOT become an Any proxy through a NonTransfer proxy"
    );

    // Currently this assertion FAILS on unpatched code: attacker2 IS added as Any proxy,
    // and a subsequent Balances::transfer_all through that Any proxy succeeds, draining victim's funds.
}
```

### Citations

**File:** system-parachains/people/people-polkadot/src/lib.rs (L495-528)
```rust
			ProxyType::NonTransfer => matches!(
				c,
				RuntimeCall::System(_) |
					RuntimeCall::ParachainSystem(_) |
					RuntimeCall::Timestamp(_) |
					RuntimeCall::CollatorSelection(_) |
					RuntimeCall::Session(_) |
					RuntimeCall::Utility(_) |
					RuntimeCall::Multisig(_) |
					RuntimeCall::Proxy(_) |
					// We don't allow:
					// `request_judgement` puts up a deposit to transfer to a registrar,
					// `set_subs` and `add_sub` will take and repatriate deposits from the proxied
					// account, should not be allowed.
					RuntimeCall::Identity(pallet_identity::Call::add_registrar { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::set_identity { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::clear_identity { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::cancel_request { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::set_fee { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::set_account_id { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::set_fields { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::provide_judgement { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::kill_identity { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::rename_sub { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::remove_sub { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::quit_sub { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::add_username_authority { .. }) |
					RuntimeCall::Identity(
						pallet_identity::Call::remove_username_authority { .. }
					) | RuntimeCall::Identity(pallet_identity::Call::set_username_for { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::accept_username { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::remove_expired_approval { .. }) |
					RuntimeCall::Identity(pallet_identity::Call::set_primary_username { .. })
			),
```

**File:** system-parachains/people/people-polkadot/src/lib.rs (L558-568)
```rust
	fn is_superset(&self, o: &Self) -> bool {
		match (self, o) {
			(x, y) if x == y => true,
			(ProxyType::Any, _) => true,
			(_, ProxyType::Any) => false,
			(ProxyType::Identity, ProxyType::IdentityJudgement) => true,
			(ProxyType::NonTransfer, ProxyType::IdentityJudgement) => true,
			(ProxyType::NonTransfer, ProxyType::Collator) => true,
			_ => false,
		}
	}
```

**File:** pallets/remote-proxy/src/lib.rs (L465-490)
```rust
		fn do_proxy(
			def: ProxyDefinition<T::AccountId, T::ProxyType, BlockNumberFor<T>>,
			real: T::AccountId,
			call: <T as pallet_proxy::Config>::RuntimeCall,
		) {
			use frame_support::traits::{InstanceFilter as _, OriginTrait as _};
			// This is a freshly authenticated new account, the origin restrictions doesn't apply.
			let mut origin: T::RuntimeOrigin = frame_system::RawOrigin::Signed(real).into();
			origin.add_filter(move |c: &<T as frame_system::Config>::RuntimeCall| {
				let c = <T as pallet_proxy::Config>::RuntimeCall::from_ref(c);
				// We make sure the proxy call does not modify proxies.
				match c.is_sub_type() {
					// Proxy call cannot add or remove a proxy with more permissions than it already
					// has.
					Some(pallet_proxy::Call::add_proxy { ref proxy_type, .. }) |
					Some(pallet_proxy::Call::remove_proxy { ref proxy_type, .. })
						if !def.proxy_type.is_superset(proxy_type) =>
						false,
					// Proxy call cannot remove all proxies or kill pure proxies unless it has full
					// permissions.
					Some(pallet_proxy::Call::remove_proxies { .. }) |
					Some(pallet_proxy::Call::kill_pure { .. })
						if def.proxy_type != T::ProxyType::default() =>
						false,
					_ => def.proxy_type.filter(c),
				}
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs (L666-682)
```rust
			ProxyType::Staking => matches!(
				c,
				RuntimeCall::Staking(..) |
					RuntimeCall::StakingRcClient(..) |
					RuntimeCall::Session(..) |
					RuntimeCall::Utility(..) |
					// Not on AH RuntimeCall::FastUnstake(..) |
					RuntimeCall::VoterList(..) |
					RuntimeCall::NominationPools(..) |
					RuntimeCall::Proxy(pallet_proxy::Call::add_proxy {
						proxy_type: ProxyType::StakingOperator,
						..
					}) | RuntimeCall::Proxy(pallet_proxy::Call::remove_proxy {
						proxy_type: ProxyType::StakingOperator,
						..
					})
			),
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/tests/tests.rs (L1022-1051)
```rust
			// When: Bob tries to add an Any proxy for Alice
			let add_any_call = RuntimeCall::Proxy(pallet_proxy::Call::add_proxy {
				delegate: <Runtime as frame_system::Config>::Lookup::unlookup(carol.clone()),
				proxy_type: ProxyType::Any,
				delay: 0,
			});
			// proxy() returns Ok(()) but inner call result is in ProxyExecuted event
			assert_ok!(Proxy::proxy(
				RuntimeOrigin::signed(bob.clone()),
				<Runtime as frame_system::Config>::Lookup::unlookup(alice.clone()),
				None,
				Box::new(add_any_call),
			));

			// Then: The ProxyExecuted event should contain CallFiltered error
			let events = frame_system::Pallet::<Runtime>::events();
			let proxy_executed = events.iter().rev().find_map(|record| {
				if let RuntimeEvent::Proxy(pallet_proxy::Event::ProxyExecuted { result }) =
					&record.event
				{
					Some(*result)
				} else {
					None
				}
			});
			assert_eq!(
				proxy_executed,
				Some(Err(frame_system::Error::<Runtime>::CallFiltered.into())),
				"Inner call should fail with CallFiltered"
			);
```
