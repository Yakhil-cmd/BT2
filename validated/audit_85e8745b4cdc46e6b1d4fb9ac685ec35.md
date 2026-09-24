## Finding: Privilege Escalation in the Relay-Chain `Proxy::NonTransfer` Filter/`is_superset` Lattice

This is the same bug class that Elasticsearch had (an attacker able to legitimately request one authorization level uses it to mint itself a *different*, more powerful authorization level, because the privilege-check function and the actual permission-check function disagree). In the Polkadot SDK, `pallet_proxy` is the analogous "API key" system: `ProxyType::filter()` decides what a delegate may execute, and `ProxyType::is_superset()` is the sole gate that decides whether one proxy type may create/remove another proxy type of a *different* kind [1](#0-0) . If `is_superset()` claims a relationship that `filter()` does not actually honor, a low-privilege proxy can mint itself a proxy type whose filter admits calls the original type explicitly denies — exactly the CVE-2020-7009 pattern.

Parity already found and fixed one instance of this on `asset-hub-westend`/`asset-hub-rococo` (`NonTransfer` falsely claiming to be a superset of `Governance`), tracked in [2](#0-1)  with a regression test [3](#0-2) .

The same bug class still exists, unpatched, on the **relay-chain runtimes** (`polkadot/runtime/westend` and `polkadot/runtime/rococo`).

### Title
`NonTransfer` proxy escalates to `Registrar::swap` via a broken `is_superset`/`filter` lattice - (File: `polkadot/runtime/westend/src/lib.rs`, `polkadot/runtime/rococo/src/lib.rs`)

### Summary
On the Westend and Rococo relay-chain runtimes, `ProxyType::is_superset` returns `true` for `(ProxyType::NonTransfer, _)` unconditionally — i.e. `NonTransfer` claims to be a superset of *every* other `ProxyType`, including `Auction` [4](#0-3) [5](#0-4) . But `NonTransfer`'s own `filter` explicitly excludes `Registrar::swap` while `Auction`'s `filter` admits the entire `Registrar` call family, including `swap`: [6](#0-5) [7](#0-6) 

Because `pallet_proxy::do_proxy` gates `add_proxy`/`remove_proxy` purely on `is_superset` (not `filter`) [8](#0-7) , a delegate holding only a `NonTransfer` proxy over a victim account can add itself an `Auction` proxy for that same victim, then invoke `Registrar::swap` on the victim's behalf — a capability that `NonTransfer` was specifically designed to deny.

### Finding Description
`pallet_proxy::Pallet::proxy` dispatches the delegate-supplied call under a filtered origin built from the delegate's `ProxyDefinition` [9](#0-8) . The origin filter installed in `do_proxy` intercepts `Call::add_proxy`/`Call::remove_proxy` and blocks them only `if !def.proxy_type.is_superset(proxy_type)`; for anything else (including the `add_proxy` call falling through to the default arm) it defers to `def.proxy_type.filter(c)` [10](#0-9) .

On Westend/Rococo relay runtimes:
- `NonTransfer.is_superset(&Auction)` → `true` (blanket rule) [11](#0-10) .
- `NonTransfer.filter(&Proxy::add_proxy{..})` → `true`, because `NonTransfer`'s filter admits the entire `RuntimeCall::Proxy(..)` family unconditionally [12](#0-11) .

So the `is_superset` check never blocks, and the `add_proxy` call is dispatched with the victim as signer, registering the attacker as an `Auction` proxy for the victim.

`Auction.filter` admits `RuntimeCall::Registrar(..)` unconditionally, i.e. every `paras_registrar` call including `swap` [13](#0-12) . But `NonTransfer.filter` deliberately excludes `Registrar::swap` while admitting `register`/`deregister`/`reserve` — the comment "Specifically omitting Registrar `swap`" makes the intent explicit [14](#0-13) . `swap()` requires the caller to be Root, the para itself, or the para's owner [15](#0-14) ; the delegator (`real`) account is what is checked, since the proxy dispatches as `Signed(real)`.

### Impact Explanation
A delegate who was only ever granted the deliberately-restricted `NonTransfer` proxy type over a para-owning account can bootstrap itself an `Auction` proxy for the same account and then invoke `Registrar::swap` as that account — the exact call `NonTransfer` was designed to forbid. `swap` exchanges the on-demand/lease-holding status (and associated crowdloan funds, lease data, auction deposit) between two `ParaId`s [16](#0-15) , which can be used to disrupt or hijack a parachain slot/lease relationship that the true owner never authorized through this restricted delegate. This is an authorization-bypass ("improper privilege management") directly analogous to the reported Elasticsearch CVE: a low-privilege, self-service grant is abused to mint a higher-privilege grant.

### Likelihood Explanation
Requires only a signed extrinsic from an existing `NonTransfer` proxy delegate — no governance, no stolen keys, no validator/collator collusion. The only precondition is that the account owning the `NonTransfer` proxy relationship is (or later becomes) the manager/owner of a `ParaId`, which is a normal, expected relationship (crowdloan/parachain-slot owners commonly delegate `NonTransfer` proxies for convenience).

### Recommendation
Remove the blanket `(ProxyType::NonTransfer, _) => true` rule in `polkadot/runtime/westend/src/lib.rs` and `polkadot/runtime/rococo/src/lib.rs` and replace it with an explicit, per-variant list — mirroring the fix already applied to `asset-hub-westend`/`asset-hub-rococo` in PR 12769 — so that `is_superset` only holds for types whose `filter` is a genuine superset of the target type's `filter`. Add a lattice-consistency test analogous to `proxy_type_superset_relation_matches_call_filters` in `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs` for the relay-chain runtimes to prevent regressions.

### Proof of Concept
Not executed against a live network. Logical trace through the existing code paths (all citations above) demonstrates the reachable exploit:
1. Victim `V` grants attacker `A` a `NonTransfer` proxy: `Proxy::add_proxy(origin=V, delegate=A, proxy_type=NonTransfer, delay=0)`.
2. `A` calls `Proxy::proxy(origin=A, real=V, force_proxy_type=None, call=Proxy::add_proxy{delegate: A, proxy_type: Auction, delay: 0})`. The `do_proxy` origin filter evaluates `!NonTransfer.is_superset(&Auction)` = `false` (blanket rule), falls through to `NonTransfer.filter(add_proxy_call)` = `true` (Proxy pallet unconditionally admitted) → dispatch succeeds, `A` is now registered as an `Auction` proxy for `V`.
3. `A` calls `Proxy::proxy(origin=A, real=V, force_proxy_type=Some(Auction), call=Registrar::swap{id: V_owned_para, other: target_para})`. `Auction.filter` admits `Registrar::swap` unconditionally → dispatched as `Signed(V)`. `ensure_root_para_or_owner` succeeds because `V` is the actual owner of `id`.
4. Result: `A`, holding only a `NonTransfer` grant, executed `Registrar::swap` on `V`'s behalf — a call `NonTransfer`'s own filter explicitly denies.

No mocked authority or forged proof is used; every step goes through the real `pallet_proxy` dispatch and origin-filter machinery and the real `paras_registrar::swap` extrinsic, gated only by the runtime's own (broken) `InstanceFilter` implementation.

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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2518-2559)
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

	// The other declared `NonTransfer` subsets are unaffected.
	for subset in [
		ProxyType::Collator,
		ProxyType::Staking,
		ProxyType::NominationPools,
		ProxyType::StakingOperator,
	] {
		assert!(ProxyType::NonTransfer.is_superset(&subset));
	}
}
```

**File:** polkadot/runtime/westend/src/lib.rs (L954-1010)
```rust
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

**File:** polkadot/runtime/rococo/src/lib.rs (L960-995)
```rust
				RuntimeCall::Registrar(paras_registrar::Call::register {..}) |
				RuntimeCall::Registrar(paras_registrar::Call::deregister {..}) |
				// Specifically omitting Registrar `swap`
				RuntimeCall::Registrar(paras_registrar::Call::reserve {..}) |
				RuntimeCall::Crowdloan(..) |
				RuntimeCall::Slots(..) |
				RuntimeCall::Auctions(..) // Specifically omitting the entire XCM Pallet
			),
			ProxyType::Governance => matches!(
				c,
				RuntimeCall::Bounties(..) |
					RuntimeCall::Utility(..) |
					RuntimeCall::ChildBounties(..) |
					// OpenGov calls
					RuntimeCall::ConvictionVoting(..) |
					RuntimeCall::Referenda(..) |
					RuntimeCall::FellowshipCollective(..) |
					RuntimeCall::FellowshipReferenda(..) |
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
				RuntimeCall::Auctions { .. } |
					RuntimeCall::Crowdloan { .. } |
					RuntimeCall::Registrar { .. } |
					RuntimeCall::Multisig(..) |
					RuntimeCall::Slots { .. }
			),
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

**File:** polkadot/runtime/common/src/paras_registrar/mod.rs (L316-374)
```rust
		/// Swap a lease holding parachain with another parachain, either on-demand or lease
		/// holding.
		///
		/// The origin must be Root, the `para` owner, or the `para` itself.
		///
		/// The swap will happen only if there is already an opposite swap pending. If there is not,
		/// the swap will be stored in the pending swaps map, ready for a later confirmatory swap.
		///
		/// The `ParaId`s remain mapped to the same head data and code so external code can rely on
		/// `ParaId` to be a long-term identifier of a notional "parachain". However, their
		/// scheduling info (i.e. whether they're an on-demand parachain or lease holding
		/// parachain), auction information and the auction deposit are switched.
		#[pallet::call_index(3)]
		#[pallet::weight(<T as Config>::WeightInfo::swap())]
		pub fn swap(origin: OriginFor<T>, id: ParaId, other: ParaId) -> DispatchResult {
			Self::ensure_root_para_or_owner(origin, id)?;

			// If `id` and `other` is the same id, we treat this as a "clear" function, and exit
			// early, since swapping the same id would otherwise be a noop.
			if id == other {
				PendingSwap::<T>::remove(id);
				return Ok(());
			}

			// Sanity check that `id` is even a para.
			let id_lifecycle =
				paras::Pallet::<T>::lifecycle(id).ok_or(Error::<T>::NotRegistered)?;

			if PendingSwap::<T>::get(other) == Some(id) {
				let other_lifecycle =
					paras::Pallet::<T>::lifecycle(other).ok_or(Error::<T>::NotRegistered)?;
				// identify which is a lease holding parachain and which is a parathread (on-demand
				// parachain)
				if id_lifecycle == ParaLifecycle::Parachain &&
					other_lifecycle == ParaLifecycle::Parathread
				{
					Self::do_thread_and_chain_swap(id, other);
				} else if id_lifecycle == ParaLifecycle::Parathread &&
					other_lifecycle == ParaLifecycle::Parachain
				{
					Self::do_thread_and_chain_swap(other, id);
				} else if id_lifecycle == ParaLifecycle::Parachain &&
					other_lifecycle == ParaLifecycle::Parachain
				{
					// If both chains are currently parachains, there is nothing funny we
					// need to do for their lifecycle management, just swap the underlying
					// data.
					T::OnSwap::on_swap(id, other);
				} else {
					return Err(Error::<T>::CannotSwap.into());
				}
				Self::deposit_event(Event::<T>::Swapped { para_id: id, other_id: other });
				PendingSwap::<T>::remove(other);
			} else {
				PendingSwap::<T>::insert(id, other);
			}

			Ok(())
		}
```
