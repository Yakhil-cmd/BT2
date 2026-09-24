### Title
`ProxyType::NonTransfer` falsely claims superset over `ProxyType::Auction`, letting a non-transfer proxy escalate into `paras_registrar::swap` and steal a lease-holding parachain slot - ([File: polkadot/runtime/westend/src/lib.rs])

### Summary
This is the exact same bug class the codebase already fixed once for Asset Hub Westend (`prdoc/pr_12769.prdoc`, regression test `non_transfer_proxy_is_not_a_superset_of_governance`, upstream issue [paritytech/polkadot-sdk#12724](https://github.com/paritytech/polkadot-sdk/issues/12724)): `pallet_proxy` authorizes `add_proxy`/`remove_proxy` purely via `InstanceFilter::is_superset`, independent of `InstanceFilter::filter`. If a "declared superset" proxy type's `filter` is actually narrower than a "subset" type's `filter` for some call, a delegate holding the "superset" proxy can self-escalate by minting itself the "subset" proxy type and dispatching the call the superset type itself was supposed to deny.

That exact mismatch still exists, unpatched, between `ProxyType::NonTransfer` and `ProxyType::Auction` in the relay-chain `ProxyType::is_superset` implementation, which unconditionally returns `true` for `(NonTransfer, _)` except `Any`: [1](#0-0) 

`ProxyType::Auction` admits the entire `Registrar` pallet unrestricted: [2](#0-1) 

But `ProxyType::NonTransfer`'s own filter deliberately excludes `Registrar::swap`, admitting only `register`, `deregister`, and `reserve`, with an explicit comment marking the omission as intentional: [3](#0-2) 

Since `Auction`'s filter is a strict superset of `NonTransfer`'s with respect to `Registrar` calls, but `is_superset` still claims `NonTransfer ⊇ Auction`, `pallet_proxy::do_proxy`'s guard (`!def.proxy_type.is_superset(proxy_type) => false`) never blocks a `NonTransfer` delegate from calling `add_proxy`/`remove_proxy` with `proxy_type: Auction`: [4](#0-3) 

The same pattern (identical `ProxyType` enum, identical comment, identical `is_superset`) is duplicated in `polkadot/runtime/rococo/src/lib.rs` and in the new staking-async relay-chain template `substrate/frame/staking-async/runtimes/rc/src/lib.rs`, confirmed via `grep_search` for `ProxyType::Auction =>` and `Specifically omitting Registrar` matching all three files. It is not present in the Kusama/Polkadot production relay-chain runtimes, which have moved this logic to Asset Hub as part of the Asset Hub Migration (AHM) and already carry the fixed `is_superset`/lattice-check pattern seen on Asset Hub Westend.

### Finding Description
`paras_registrar::Pallet::swap` (`polkadot/runtime/common/src/paras_registrar/mod.rs:330`) authorizes with `Self::ensure_root_para_or_owner(origin, id)?`, i.e. Root, the parachain's own XCM origin, or the account registered as `id`'s manager — a permissionless role obtained simply by calling `reserve`/`register`, no governance or validator privilege required: [5](#0-4) 

`swap` completes only when both sides have an opposing pending swap recorded (`PendingSwap::<T>::get(other) == Some(id)`), at which point it invokes `T::OnSwap::on_swap(id, other)`, which for the slots pallet swaps the two `ParaId`s' `Leases` entries wholesale: [6](#0-5) 

Attack path:
1. Victim `R` owns a valuable lease-holding parachain `A` and, for convenience/automation, grants a `NonTransfer` proxy to delegate `D`. `R` never intends `D` to be able to move `A`'s ownership/lease data — this is precisely why the runtime authors wrote "Specifically omitting Registrar `swap`" into `NonTransfer`'s filter.
2. Attacker (controlling `D`, or a colluding second account) separately registers a worthless on-demand parathread `B` under their own signature (permissionless, no proxy needed) and calls `Registrar::swap(signed(attacker), B, A)`, inserting `PendingSwap::<T>::insert(B, A)`.
3. `D`, using its `NonTransfer` proxy over `R`, calls `Proxy::add_proxy(real=R, delegate=D_or_attacker2, proxy_type=Auction)`. Because `ProxyType::is_superset(NonTransfer, Auction)` incorrectly returns `true`, `pallet_proxy`'s guard does not reject this even though `NonTransfer`'s own filter would reject the underlying `Registrar::swap` call.
4. The newly minted `Auction`-typed proxy calls `Registrar::swap(id=A, other=B)` on behalf of `R`. `PendingSwap::get(B) == Some(A)` is already satisfied from step 2, so the swap executes immediately, transferring `R`'s valuable parachain lease/slot data to the attacker's worthless `ParaId`.

This is a direct analog of the immich CVE: an entity (a limited-privilege API key / a `NonTransfer` proxy) is supposed to be barred from a specific privileged action (granting itself admin / executing `Registrar::swap`), but a missing consistency check between the declared privilege hierarchy (`is_superset`) and the actual permission check (`filter`/API-key scope enforcement) lets it grant itself broader access and perform exactly the forbidden action.

### Impact Explanation
Impact is theft/irreversible loss of a parachain's lease-holding slot and associated on-chain identity data (crowdloan fund association, lease schedule) — a high-value, illiquid asset — achieved purely by abusing a proxy relationship the owner explicitly scoped to exclude fund/asset-moving operations. This matches "Critical/High theft ... irreversible" criteria in the assessment guidance. The attacker needs no privileged role, governance control, or stolen keys — only an existing (routine, commonly granted) `NonTransfer` proxy delegation and ownership of a throwaway `ParaId`.

### Likelihood Explanation
Requires the victim to have granted a `NonTransfer` proxy to an account that later turns malicious (or is compromised) — a realistic and common setup pattern (delegating "everything except moving funds"), and requires the target account to actually manage a lease-holding parachain. Given the currently confirmed presence of the exact same architecture flaw as a previously-fixed live issue (PR #12769 / GHSA for the `Governance` pair), and its unpatched persistence for the `Auction`/`Registrar::swap` pair, likelihood of latent exploitability is meaningful wherever this `ProxyType` implementation is deployed (Westend, Rococo, and any chain built from the staking-async `rc` runtime template).

### Recommendation
Fix `ProxyType::is_superset` for the relay-chain `ProxyType` in `polkadot/runtime/westend/src/lib.rs`, `polkadot/runtime/rococo/src/lib.rs`, and `substrate/frame/staking-async/runtimes/rc/src/lib.rs` the same way it was fixed for Asset Hub Westend: either derive `is_superset` mechanically from `filter` (as the Asset Hub Westend regression test `proxy_type_superset_relation_matches_call_filters` now enforces), or explicitly exclude `Auction` from `NonTransfer`'s claimed subset list. Add the equivalent lattice-consistency regression test to these runtimes' test suites so this bug class cannot silently reappear on another `ProxyType` pair.

### Proof of Concept
Not executed against a live network. A minimal local reproduction would use `polkadot/runtime/westend/src/lib.rs`'s `ProxyType` together with `pallet-proxy`'s and `paras_registrar`'s test harnesses (as already exercised by `polkadot/runtime/common/src/paras_registrar/tests.rs::swap_works` and `substrate/frame/proxy/src/tests.rs::filtering_works`), asserting:
1. `ProxyType::Auction.filter(&RuntimeCall::Registrar(paras_registrar::Call::swap { .. }))` returns `true`.
2. `ProxyType::NonTransfer.filter(&RuntimeCall::Registrar(paras_registrar::Call::swap { .. }))` returns `false`.
3. `ProxyType::NonTransfer.is_superset(&ProxyType::Auction)` currently returns `true` (the failed guard) — this assertion should fail once fixed.
4. An integration test analogous to `pure_proxy_stash_can_delegate_to_staking_operator` where a `NonTransfer` proxy calls `Proxy::add_proxy(.., ProxyType::Auction, ..)` succeeds today, then the newly added `Auction` delegate successfully dispatches `Registrar::swap` on behalf of the real account — demonstrating the escalation end-to-end.

I was not able to execute this PoC (no test/terminal access in this environment); the above is the concrete reproduction path derivable from the cited source, not a claimed test run.

### Citations

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

**File:** polkadot/runtime/common/src/paras_registrar/mod.rs (L316-338)
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
```

**File:** polkadot/runtime/common/src/slots/mod.rs (L332-336)
```rust
impl<T: Config> crate::traits::OnSwap for Pallet<T> {
	fn on_swap(one: ParaId, other: ParaId) {
		Leases::<T>::mutate(one, |x| Leases::<T>::mutate(other, |y| core::mem::swap(x, y)))
	}
}
```
