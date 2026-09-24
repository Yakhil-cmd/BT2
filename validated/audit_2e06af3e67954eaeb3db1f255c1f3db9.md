### Title
`pallet_safe_mode` / `pallet_tx_pause` call filters block governance cancellation (`Democracy::emergency_cancel`/`veto_external`, `Referenda::cancel`/`kill`) while Root-origin scheduled enactments bypass the filter, shrinking the effective veto window - ([File: substrate/bin/node/runtime/src/lib.rs])

### Summary
The Telcoin report shows that a pause mechanism (`whenNotPaused`) is applied to a *challenge* function but not to the malicious proposal's *execution* path, so a pause window can be exploited to shrink or eliminate the challenge period. The same asymmetry exists in the reference node runtime: `pallet_safe_mode` and `pallet_tx_pause` gate dispatched extrinsics (including the privileged cancel/veto calls of `pallet_democracy`/`pallet_referenda`) via `frame_system::Config::BaseCallFilter`, but the automatic enactment of an already-approved proposal is dispatched by `pallet_scheduler`'s `on_initialize` with the `RawOrigin::Root` origin, which is explicitly documented to bypass `BaseCallFilter`.

### Finding Description
`pallet_democracy::bake_referendum` schedules the winning proposal via `T::Scheduler::schedule_named(..., frame_system::RawOrigin::Root.into(), status.proposal)` [1](#0-0) . `pallet_scheduler`'s own documentation states that scheduled calls are dispatched with the origin's default `BaseCallFilter` "for all origin except root which will get no filter" [2](#0-1) , meaning a Root-origin scheduled enactment executes unconditionally in `on_initialize`, unaffected by any call filter installed via `BaseCallFilter`.

Meanwhile, both `pallet_safe_mode` and `pallet_tx_pause` operate by composing into `frame_system::Config::BaseCallFilter` and blocking every non-whitelisted dispatched call while active: `pallet_safe_mode::Pallet::is_allowed` returns `T::WhitelistedCalls::contains(call)` whenever safe-mode `is_entered()` [3](#0-2) , and `pallet_tx_pause::Pallet::contains` returns `!is_paused_unbound(...)` for any paused call name [4](#0-3) .

In the reference `node` runtime, the whitelist for safe-mode only exempts `System`, `SafeMode`, and `TxPause` calls [5](#0-4) , and the tx-pause whitelist only exempts `Balances::transfer_keep_alive` [6](#0-5) . Democracy's privileged cancellation/veto extrinsics (`emergency_cancel`, `veto_external`, guarded by `CancellationOrigin`/`VetoOrigin`) and Referenda's `cancel`/`kill` (guarded by `T::CancelOrigin`/`T::KillOrigin`) are ordinary dispatched calls, none of which appear in either whitelist, so they are blocked like any other extrinsic while safe-mode or tx-pause is active. In contrast, the automatic enactment step that finally executes the approved proposal - `bake_referendum`'s `schedule_named(... RawOrigin::Root ...)` and `pallet_referenda::schedule_enactment` when the origin resolves to Root - runs through `on_initialize` and, per the scheduler's own documented semantics, is not subject to `BaseCallFilter` at all.

This precisely reproduces the reported bug class: a permissionless actor can propose/submit a proposal (via `Democracy::propose`/`public_propose` or `Referenda::submit`, which require no privileged role) and if a `SafeMode`/`TxPause` pause window (owner/root-triggered, or permissionlessly by anyone posting a deposit for `pallet_safe_mode::enter`) coincides with or is timed around the decision/enactment window, the privileged council/committee members who would otherwise call `emergency_cancel`/`veto_external`/`cancel`/`kill` cannot do so, while the scheduled Root-origin enactment proceeds unimpeded once due, shrinking or nullifying the effective veto period, exactly like `TelcoinDistributor.challengeTransaction()` being blocked by `whenNotPaused` while execution is unaffected.

### Impact Explanation
If exploited, a malicious or erroneous already-approved governance proposal (dispatched with Root/`system::RawOrigin::Root` origin via the scheduler) could execute without any opportunity for privileged cancellation/veto during a pause window, since the veto/cancel extrinsics are filtered but the scheduled Root enactment is not. This could allow root-level state mutations (arbitrary runtime calls under `Root` origin) to complete despite an active safeguard mechanism intended to halt state-changing activity. This aligns with a Medium-severity classification, matching the original report's severity, since it requires a specific pre-condition (pause window timing) and existing privileged actors (council/committee) rather than a raw permissionless exploit path, but breaks an explicit governance safety invariant.

### Likelihood Explanation
Exploitability depends on: (1) `pallet_safe_mode`/`pallet_tx_pause` being included in a production runtime with a whitelist that omits `Democracy`/`Referenda` cancellation calls (true of the reference node runtime as configured), and (2) the timing of a pause window overlapping with a proposal's decision/enactment window — either coincidentally, or via `pallet_safe_mode::enter`, which is itself permissionlessly callable by depositing funds (`EnterDepositAmount`), giving an attacker some ability to trigger pause windows without privilege. This is analogous to the front-running/timing element in the original report, and the provided repository shows the governance-cancel calls are not exempted from either pause pallet's whitelist by default.

### Recommendation
Add the privileged cancellation/veto dispatchables of `pallet_democracy` (`emergency_cancel`, `veto_external`) and `pallet_referenda` (`cancel`, `kill`) — and any other governance safety-valve calls — to the `WhitelistedCalls` implementations for both `pallet_safe_mode` (`SafeModeWhitelistedCalls`) and `pallet_tx_pause` (`TxPauseWhitelistedCalls`) in the runtime configuration, so that cancellation/veto authority remains available while the system is paused, consistent with the original report's recommendation to exempt the challenge/veto path from the pause modifier.

### Proof of Concept
No local Rust/FRAME reproduction was executed. This is a static-analysis analog derived from source inspection: (1) `pallet_scheduler`'s documented Root-origin filter bypass [2](#0-1) , (2) `pallet_democracy::bake_referendum` scheduling enactment with `RawOrigin::Root` [1](#0-0) , and (3) the reference runtime's narrow whitelists for both pause pallets that exclude Democracy/Referenda cancellation calls [7](#0-6) . I was unable to inspect the exact line ranges/origins for `Democracy::emergency_cancel`/`veto_external` and the runtime's `CancellationOrigin`/`VetoOrigin` configuration in this session (grep confirmed their existence but line-level content was not retrieved), so the precise privileged-origin wiring for those two extrinsics is not fully verified here and should be confirmed in a follow-up before treating this as conclusively reproducible.

### Citations

**File:** substrate/frame/democracy/src/lib.rs (L1608-1621)
```rust
			// Earliest it can be scheduled for is next block.
			let when = now.saturating_add(status.delay.max(One::one()));
			if T::Scheduler::schedule_named(
				(DEMOCRACY_ID, index).encode_into::<_, T::Hashing>(),
				DispatchTime::At(when),
				None,
				63,
				frame_system::RawOrigin::Root.into(),
				status.proposal,
			)
			.is_err()
			{
				frame_support::print("LOGIC ERROR: bake_referendum/schedule_named failed");
			}
```

**File:** substrate/frame/scheduler/src/lib.rs (L34-39)
```rust
//! be canceled.
//!
//! __NOTE:__ Instead of using the filter contained in the origin to call `fn schedule`, scheduled
//! runtime calls will be dispatched with the default filter for the origin: namely
//! `frame_system::Config::BaseCallFilter` for all origin types (except root which will get no
//! filter).
```

**File:** substrate/frame/safe-mode/src/lib.rs (L582-598)
```rust
	/// Return whether the given call is allowed to be dispatched.
	pub fn is_allowed(call: &T::RuntimeCall) -> bool
	where
		T::RuntimeCall: GetCallMetadata,
	{
		let CallMetadata { pallet_name, .. } = call.get_call_metadata();
		// SAFETY: The `SafeMode` pallet is always allowed.
		if pallet_name == <Pallet<T> as PalletInfoAccess>::name() {
			return true;
		}

		if Self::is_entered() {
			T::WhitelistedCalls::contains(call)
		} else {
			true
		}
	}
```

**File:** substrate/frame/tx-pause/src/lib.rs (L279-288)
```rust
impl<T: pallet::Config> Contains<<T as frame_system::Config>::RuntimeCall> for Pallet<T>
where
	<T as frame_system::Config>::RuntimeCall: GetCallMetadata,
{
	/// Return whether the call is allowed to be dispatched.
	fn contains(call: &<T as frame_system::Config>::RuntimeCall) -> bool {
		let CallMetadata { pallet_name, function_name } = call.get_call_metadata();
		!Pallet::<T>::is_paused_unbound(pallet_name.into(), function_name.into())
	}
}
```

**File:** substrate/bin/node/runtime/src/lib.rs (L239-260)
```rust
/// Calls that can bypass the safe-mode pallet.
pub struct SafeModeWhitelistedCalls;
impl Contains<RuntimeCall> for SafeModeWhitelistedCalls {
	fn contains(call: &RuntimeCall) -> bool {
		match call {
			RuntimeCall::System(_) | RuntimeCall::SafeMode(_) | RuntimeCall::TxPause(_) => true,
			_ => false,
		}
	}
}

/// Calls that cannot be paused by the tx-pause pallet.
pub struct TxPauseWhitelistedCalls;
/// Whitelist `Balances::transfer_keep_alive`, all others are pauseable.
impl Contains<RuntimeCallNameOf<Runtime>> for TxPauseWhitelistedCalls {
	fn contains(full_name: &RuntimeCallNameOf<Runtime>) -> bool {
		match (full_name.0.as_slice(), full_name.1.as_slice()) {
			(b"Balances", b"transfer_keep_alive") => true,
			_ => false,
		}
	}
}
```
