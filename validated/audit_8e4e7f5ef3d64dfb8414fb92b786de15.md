No vulnerability found for this question.

The original report's root cause is a privileged "pauser role" freezing user withdrawals with no emergency-exit path. In Polkadot SDK, the closest analogs are `pallet-tx-pause` and `pallet-safe-mode`, but both differ from the reported bug class in ways that break the analogy:

1. Pausing requires a privileged, governance-bound origin (`T::PauseOrigin`, typically root/council), not an unprivileged attacker-controlled input [1](#0-0) . The scan's threat model explicitly excludes privileged/governance-controlled actions as attack vectors.

2. `pallet-tx-pause` is designed with a mandatory whitelist mechanism specifically to prevent full fund lock-up: `TxPauseWhitelistedCalls`/`WhitelistedCalls` cannot be paused, and the reference runtime explicitly whitelists `Balances::transfer_keep_alive` so a fund-exit path always remains available even if all else is paused [2](#0-1) [3](#0-2) .

3. `pallet-safe-mode` similarly has a `ForceExitOrigin` and its own `SafeModeWhitelistedCalls` (allowing `System`/`SafeMode`/`TxPause` calls through), plus a bounded `ReleaseDelay`, so safe-mode cannot indefinitely and unconditionally trap funds without any override [4](#0-3) [5](#0-4) .

4. The `TransactionPause` trait's own documentation states the invariant that "everything that is paused, can be un-paused," reinforcing that this is an intentional, reversible governance safety switch rather than a bug [6](#0-5) .

Because triggering the "pause blocks withdrawal" condition requires a privileged/root-level actor (explicitly out of scope per the given threat model) and the design already builds in whitelisting/force-exit to prevent indefinite fund freezing, there is no demonstrable Polkadot SDK analog matching the reported EVM vulnerability under the stated constraints.

### Citations

**File:** substrate/frame/tx-pause/src/lib.rs (L193-199)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::pause())]
		pub fn pause(origin: OriginFor<T>, full_name: RuntimeCallNameOf<T>) -> DispatchResult {
			T::PauseOrigin::ensure_origin(origin)?;

			Self::do_pause(full_name).map_err(Into::into)
		}
```

**File:** substrate/frame/tx-pause/src/lib.rs (L252-266)
```rust
	/// Ensure that this call can be paused.
	pub fn ensure_can_pause(full_name: &RuntimeCallNameOf<T>) -> Result<(), Error<T>> {
		// SAFETY: The `TxPause` pallet can never pause itself.
		if full_name.0.as_slice() == <Self as PalletInfoAccess>::name().as_bytes() {
			return Err(Error::<T>::Unpausable);
		}

		if T::WhitelistedCalls::contains(&full_name) {
			return Err(Error::<T>::Unpausable);
		}
		if Self::is_paused(&full_name) {
			return Err(Error::<T>::IsPaused);
		}
		Ok(())
	}
```

**File:** substrate/bin/node/runtime/src/lib.rs (L239-248)
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
```

**File:** substrate/bin/node/runtime/src/lib.rs (L250-260)
```rust
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

**File:** substrate/frame/safe-mode/src/lib.rs (L317-324)
```rust
		/// Can only be called by the [`Config::ForceEnterOrigin`] origin.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::force_enter())]
		pub fn force_enter(origin: OriginFor<T>) -> DispatchResult {
			let duration = T::ForceEnterOrigin::ensure_origin(origin)?;

			Self::do_enter(None, duration).map_err(Into::into)
		}
```

**File:** substrate/frame/support/src/traits/tx_pause.rs (L43-47)
```rust
	/// Unpause this call immediately.
	///
	/// This takes effect in the same block and must succeed if `is_paused` returns `true`. This
	/// invariant is important to not have un-resumable calls.
	fn unpause(call: Self::CallIdentifier) -> Result<(), TransactionPauseError>;
```
