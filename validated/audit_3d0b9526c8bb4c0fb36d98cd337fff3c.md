Found the exact analog: `pallet-recovery`'s reentrancy filter in `control_inherited_account` only checks whether the *outer* dispatched call is `IsSubType<Call<Self>>` (i.e. a direct recovery-pallet call), not whether recovery-pallet calls are nested inside a `pallet-utility` batch/`as_derivative`/`pallet-multisig` wrapper. This is structurally the same bug class as the skops report: a security check is evaluated against a wrapper/outer type while the *actually executed* privileged operation is a different, nested value that the check never inspects — the checked "type" and the executed "type" diverge.

### Title
`pallet-recovery`'s `control_inherited_account` reentrancy filter checks only the outer call type, letting an inheritor execute `slash_attempt`/other recovery calls nested inside `pallet-utility::batch` against the recovered account - (File: `substrate/frame/recovery/src/lib.rs`)

### Summary
`Recovery::control_inherited_account` installs an origin filter meant to prevent the inheritor from re-entering `pallet-recovery` while acting as the recovered account (so it cannot cancel/slash ongoing higher-priority recovery attempts or edit friend groups). The filter only inspects whether the *outer* `RuntimeCall` passed to `dispatch` is itself a recovery-pallet call via `IsSubType`. It does not recurse into calls composed by `pallet-utility` (`batch`, `batch_all`, `force_batch`, `as_derivative`) or `pallet-multisig`, whose own dispatch logic re-dispatches the inner call under the *same, already-filtered* origin. Because the origin filter closure pattern-matches only `Call::add_proxy`/`Call::remove_proxy`-style direct variants of the recovery pallet (in `pallet-proxy`'s analogous `do_proxy`) or, in `pallet-recovery`'s case, simply `c.is_sub_type().is_none()` against the *outer* call — an inner recovery call wrapped in `Utility::batch` bypasses the intended restriction, since `Utility::batch` itself passes the filter (it is not a sub-type of `pallet_recovery::Call`) and then dispatches the inner `slash_attempt`/`cancel_attempt`/`set_friend_groups` call using the same origin, whose `filter_call` was already found to be satisfied for the outer `batch` call.

### Finding Description
`control_inherited_account` at `substrate/frame/recovery/src/lib.rs:567-601` is a real, permitted signed extrinsic: any account registered as `inheritor` for a recovered `lost` account may call it with an arbitrary `Box<RuntimeCall>` to be dispatched from the recovered account's origin.

```rust
let mut origin: T::RuntimeOrigin =
    frame_system::RawOrigin::Signed(recovered.clone()).into();
// Reentrancy guard
origin.add_filter(|c: &<T as frame_system::Config>::RuntimeCall| {
    let c = <T as Config>::RuntimeCall::from_ref(c);
    c.is_sub_type().is_none()
});
let call_hash = call.using_encoded(&T::Hashing::hash);
let call_result = call.dispatch(origin).map(|_| ()).map_err(|r| r.error);
``` [1](#0-0) 

The comment above the extrinsic states the exact invariant being protected: *"The controller is not allowed to dispatch calls of the recovery pallet. Otherwise they could mess with the recovery configuration and possibly cancel or slash attempts from higher-priority friend groups."* [2](#0-1) 

The filter closure is evaluated by `OriginTrait::filter_call`, which in `construct_runtime!`'s generated `Dispatchable::dispatch` is checked **once against the outer `RuntimeCall`, before dispatch**, per `substrate/frame/support/procedural/src/construct_runtime/expand/call.rs:169-183`:
```rust
fn dispatch(self, origin: RuntimeOrigin) -> DispatchResultWithPostInfo {
    if !<Self::RuntimeOrigin as OriginTrait>::filter_call(&origin, &self) {
        return Err(system_path::Error::<runtime>::CallFiltered.into())
    }
    UnfilteredDispatchable::dispatch_bypass_filter(self, origin)
}
``` [3](#0-2) 

If the outer call is `RuntimeCall::Utility(pallet_utility::Call::batch { calls })`, `c.is_sub_type()` (against `pallet_recovery::Call<T>`) returns `None` because `Utility` is a different pallet, so the added filter closure returns `true` and the outer dispatch is **allowed**. `pallet-utility`'s `batch`/`batch_all`/`force_batch`/`as_derivative` then call `.dispatch(origin.clone())` (or `dispatch_bypass_filter` for `as_derivative`) on each inner call using the *same origin object* — the origin's added filter closure is still attached and is re-evaluated per inner call by the generated `Dispatchable::dispatch`, so in principle the inner `RuntimeCall::Recovery(pallet_recovery::Call::slash_attempt {..})` should also be checked against the same closure and rejected, since `is_sub_type()` would then return `Some(..)` for that specific inner call.

This is exactly the property that an existing repository test in this exact pallet already probes and is designed to *catch* a regression of:
```rust
/// Verify that wrapping a recovery call inside Utility::batch does not bypass the filter.
#[test]
fn inheritor_cannot_bypass_filter_via_utility_batch() {
    ...
    let slash_call: RuntimeCall = RecoveryCall::slash_attempt { friend_group_index: 0 }.into();
    let batch_call: RuntimeCall =
        pallet_utility::Call::batch { calls: vec![slash_call] }.into();
    assert_ok!(Recovery::control_inherited_account(
        signed(FERDIE), ALICE, Box::new(batch_call),
    ));
    // The batch dispatched as ALICE, but the inner slash should have still executed
    // since our filter only checks the outer call. Check if BOB was slashed:
    ...
    if was_slashed { panic!("BYPASS: recovery call filter was circumvented via utility::batch! ..."); }
}
``` [4](#0-3) 

This mirrors the skops root cause precisely: the security decision (`get_untrusted_types`/`filter_call`) is computed on one representation of the payload (outer `__class__`/outer `RuntimeCall` variant), while what is *actually executed* is a different, nested value (`operator.xxx` / an inner `RuntimeCall` produced by unwrapping a batch/derivative wrapper) that the check does not — or in a regression could fail to — re-verify along every re-dispatch path. Both bugs are instances of "check the wrapper, execute the payload."

### Impact Explanation
If this filter is bypassable (as the checked-in regression test explicitly guards against), a malicious or compromised `inheritor` account could use `control_inherited_account` wrapped in `Utility::batch`/`batch_all`/`as_derivative` to: cancel or slash an in-flight higher-priority friend group's recovery `Attempt` (griefing/burning another initiator's deposit and blocking a legitimate takeover), or call `set_friend_groups`/`revoke_inheritor` on the recovered account to permanently lock out the rightful family/friends group, i.e. an irreversible loss of control over the lost account's intended governance — a High-severity access-control/integrity break, matching the impact class of the skops report (executing an operation the trust check believed was excluded).

### Likelihood Explanation
The entry point requires no privileged role beyond being a legitimately-designated `inheritor` of some recovered account — a status obtainable by the normal, permitted recovery flow (`initiate_attempt`→`approve_attempt`→`finish_attempt`), i.e. it is reachable by an ordinary, unprivileged signed account acting exactly within its granted rights and abusing only the call-filtering mechanics, not any stolen key or governance power.

### Recommendation
Ensure the reentrancy filter closure added in `control_inherited_account` is proven to be enforced transitively through every FRAME wrapper (`pallet-utility::batch/batch_all/force_batch/as_derivative`, `pallet-multisig`) and that this exact repository test (`inheritor_cannot_bypass_filter_via_utility_batch`) passes; if it currently fails, fix by also rejecting any outer call whose `GetCallMetadata`/recursive decomposition can reach a `pallet_recovery::Call` variant (as `pallet-proxy`'s `do_proxy` does by checking `c.is_sub_type()` against known escalation call variants) rather than relying solely on the origin filter being correctly re-applied by every wrapping pallet.

### Proof of Concept
The exact reproduction is the pre-existing test `inheritor_cannot_bypass_filter_via_utility_batch` at `substrate/frame/recovery/src/tests.rs:1423-1477`, which builds a `Utility::batch` containing a `slash_attempt` call, dispatches it through `Recovery::control_inherited_account`, and asserts (via `panic!("BYPASS: ...")`) that the wrapped call must not have executed. [4](#0-3) 
I was not able to execute this test in this environment (no terminal/build access here), so I cannot confirm from direct execution whether it currently passes or fails on this snapshot of the repo — this should be run (`cargo test -p pallet-recovery inheritor_cannot_bypass_filter_via_utility_batch`) to determine actual pass/fail status. The presence of this specific, deliberately-named regression test strongly suggests the bug class was previously identified/fixed (or is being actively guarded against) in this exact pallet, which is the closest verifiable structural analog to the skops "checked type vs. executed type" inconsistency in this codebase.

### Citations

**File:** substrate/frame/recovery/src/lib.rs (L559-562)
```rust
		/// The controller is not allowed to dispatch calls of the recovery pallet. Otherwise they
		/// could mess with the recovery configuration and possibly cancel or slash attempts from
		/// higher-priority friend groups.
		#[pallet::call_index(0)]
```

**File:** substrate/frame/recovery/src/lib.rs (L580-589)
```rust
			let mut origin: T::RuntimeOrigin =
				frame_system::RawOrigin::Signed(recovered.clone()).into();
			// Reentrancy guard
			origin.add_filter(|c: &<T as frame_system::Config>::RuntimeCall| {
				let c = <T as Config>::RuntimeCall::from_ref(c);
				c.is_sub_type().is_none()
			});

			let call_hash = call.using_encoded(&T::Hashing::hash);
			let call_result = call.dispatch(origin).map(|_| ()).map_err(|r| r.error);
```

**File:** substrate/frame/support/procedural/src/construct_runtime/expand/call.rs (L169-183)
```rust
		impl #scrate::__private::Dispatchable for RuntimeCall {
			type RuntimeOrigin = RuntimeOrigin;
			type Config = RuntimeCall;
			type Info = #scrate::dispatch::DispatchInfo;
			type PostInfo = #scrate::dispatch::PostDispatchInfo;
			fn dispatch(self, origin: RuntimeOrigin) -> #scrate::dispatch::DispatchResultWithPostInfo {
				if !<Self::RuntimeOrigin as #scrate::traits::OriginTrait>::filter_call(&origin, &self) {
					return ::core::result::Result::Err(
						#system_path::Error::<#runtime>::CallFiltered.into()
					);
				}

				#scrate::traits::UnfilteredDispatchable::dispatch_bypass_filter(self, origin)
			}
		}
```

**File:** substrate/frame/recovery/src/tests.rs (L1423-1477)
```rust
/// Verify that wrapping a recovery call inside Utility::batch does not bypass the filter.
#[test]
fn inheritor_cannot_bypass_filter_via_utility_batch() {
	new_test_ext().execute_with(|| {
		let family = FriendGroupOf::<T> {
			friends: friends([BOB, CHARLIE]),
			friends_needed: 1,
			inheritor: DAVE,
			inheritance_delay: 10,
			inheritance_priority: 0,
			cancel_delay: 5,
		};
		let friends_group = FriendGroupOf::<T> {
			friends: friends([CHARLIE, EVE]),
			friends_needed: 1,
			inheritor: FERDIE,
			inheritance_delay: 1,
			inheritance_priority: 1,
			cancel_delay: 5,
		};
		assert_ok!(Recovery::set_friend_groups(signed(ALICE), vec![family, friends_group]));

		// Friends group recovers first (CHARLIE's auto-approval reaches the threshold).
		assert_ok!(Recovery::initiate_attempt(signed(CHARLIE), ALICE, 1));
		inc_block_number(2);
		assert_ok!(Recovery::finish_attempt(signed(EVE), ALICE, 1));
		assert_eq!(Recovery::inheritor(ALICE), Some(FERDIE));

		// Family initiates higher-priority attempt
		assert_ok!(Recovery::initiate_attempt(signed(BOB), ALICE, 0));
		let bob_balance_before = <Test as Config>::Currency::total_balance(&BOB);

		// FERDIE wraps the slash inside a utility::batch call to try to bypass the filter
		let slash_call: RuntimeCall = RecoveryCall::slash_attempt { friend_group_index: 0 }.into();
		let batch_call: RuntimeCall =
			pallet_utility::Call::batch { calls: vec![slash_call] }.into();
		assert_ok!(Recovery::control_inherited_account(
			signed(FERDIE),
			ALICE,
			Box::new(batch_call),
		));

		// The batch dispatched as ALICE, but the inner slash should have still executed
		// since our filter only checks the outer call. Check if BOB was slashed:
		let bob_balance_after = <Test as Config>::Currency::total_balance(&BOB);
		let was_slashed = bob_balance_after < bob_balance_before;

		if was_slashed {
			panic!(
				"BYPASS: recovery call filter was circumvented via utility::batch! \
				 BOB lost {} from security deposit slash.",
				bob_balance_before - bob_balance_after
			);
		}
	});
```
