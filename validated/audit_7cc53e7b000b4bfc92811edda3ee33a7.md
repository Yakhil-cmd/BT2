Based on my investigation, I found a structurally analogous issue in `pallet-xcm`'s remote-lock/unlock machinery (`LockAsset`/`NoteUnlockable`/`RequestUnlock`/`UnlockAsset`), which mirrors the reported pattern: a user-initiated action creates state that can only be resolved by a remote/external response, and if that response never arrives, the local state is stuck forever with no cancellation or retry path.

### Title
Locked balances via `LockAsset`/`RequestUnlock` XCM round-trip can be permanently stuck if the remote counter-chain never delivers `NoteUnlockable`/`UnlockAsset`, with no local timeout or cancellation mechanism - (File: polkadot/xcm/pallet-xcm/src/lib.rs)

### Summary
`pallet-xcm` implements `xcm_executor::traits::AssetLock` to support the `LockAsset`/`NoteUnlockable`/`RequestUnlock`/`UnlockAsset` XCM instructions, allowing an account to lock local funds and delegate the unlock authority to a remote chain ("unlocker"). Releasing the lock requires a full XCM round trip to and from that remote chain. Unlike `pallet-xcm`'s query mechanism (which at least records an informational `timeout` field), the `LockedFungibles` storage entries created by `LockAsset` have no timeout, expiry, or local cancellation path at all.

### Finding Description
`LockAsset` execution in the XCM executor calls `Config::AssetLocker::prepare_lock(...)?.enact()` and then sends a `NoteUnlockable` message to the designated `unlocker` location: [1](#0-0) 

`LockTicket::enact` immediately extends a local currency lock keyed `*b"py/xcmlk"` and records the lock in `LockedFungibles`: [2](#0-1) 

The only way to release this lock is for the owner to later send `RequestUnlock` to the `locker`/unlocker chain, which must in turn send back `UnlockAsset`, processed by `UnlockTicket::enact`, which calls `T::Currency::set_lock` to reduce/remove the lock: [3](#0-2) [4](#0-3) 

Nothing in `LockedFungibles`, `LockTicket`, or `UnlockTicket` carries a timeout or expiry block, and there is no extrinsic/instruction to forcibly cancel or reclaim a stuck lock. If the `NoteUnlockable` message to the unlocker is lost (delivery failure, weight/fee misconfiguration, channel congestion, or the remote chain not being wired to accept it), the remote chain never records the lock as unlockable — so any later `RequestUnlock` sent by the owner will legitimately fail on the remote side (`NotLocked`/`WouldClobber` in `prepare_reduce_unlockable`), because there is nothing to reduce: [5](#0-4) 

Meanwhile the local lock on the owner's own chain (created up-front, unconditionally on `LockAsset` success) persists forever, because release depends entirely on completing the round trip. This is the same bug class as the report: an unconditional, irreversible local state change (funds locked / code consumed) is made in anticipation of an external asynchronous response, and if that response never arrives, there is no local recovery function — exactly the "cancelChainlinkRequest + resubmit" gap described in the report.

### Impact Explanation
An account's own funds can become permanently locked (unspendable, though still nominally owned) if the cross-chain unlock round trip never completes — whether from transient message loss, remote misconfiguration, or the remote chain simply never having implemented/wired `AssetLocker`/`NoteUnlockable` handling correctly. This is a self-inflicted but permanent freezing of funds with no governance-free recovery path, matching the class of "irreversible freezing" the assessment scope prioritizes.

### Likelihood Explanation
This requires the runtime to enable `LockAsset`/`RequestUnlock` via the executor and for that instruction to be reachable by ordinary signed accounts (e.g., via a permitted `pallet_xcm::execute` with `LockAsset`/`RequestUnlock` in scope of `XcmExecuteFilter`, or via a full `pallet_xcm::send`). I was not able to confirm, within the remaining investigation budget, which live production runtimes (e.g., Westend, Rococo, Asset Hub) actually permit `LockAsset`/`RequestUnlock` through their `XcmExecuteFilter`/`Barrier` configuration for ordinary signed users versus restricting the feature to privileged/pallet-internal use — I only located the `AssetLocker = XcmPallet` assignment sites, not their filter reachability. This materially affects likelihood, and I am not confident enough to assert this is broadly exploitable on a live Parity bounty-eligible network without that additional confirmation. Given that, and that the underlying storage/enact code itself unambiguously has no timeout/cancellation logic, I present this as a credible but not fully confirmed Medium-severity design gap, not a confirmed live Critical/High finding.

### Recommendation
Add a timeout/expiry (analogous to `QueryStatus::Pending.timeout`) to `LockedFungibles` entries, and provide a permissioned local extrinsic (callable by the lock owner after expiry) that can release a stale lock without requiring the remote chain's cooperation — mirroring the report's recommended mitigation of allowing the affected party to cancel and retry/reclaim after a timeout, rather than leaving recovery entirely contingent on a remote chain's response.

### Proof of Concept
No executable PoC was run. This report is a code-level structural analog derived from reading `polkadot/xcm/pallet-xcm/src/lib.rs` (`LockTicket::enact`, `UnlockTicket::enact`, `ReduceTicket::enact`, `AssetLock` impl) and `polkadot/xcm/xcm-executor/src/lib.rs` (`LockAsset`/`UnlockAsset`/`NoteUnlockable`/`RequestUnlock` instruction handlers), confirming the absence of any timeout or cancellation field/logic. I was unable to confirm production-runtime reachability (`XcmExecuteFilter` permissions for signed accounts) in the time available, so eligibility/likelihood should be verified further before treating this as a confirmed live-network finding.

### Citations

**File:** polkadot/xcm/xcm-executor/src/lib.rs (L1708-1724)
```rust
			LockAsset { asset, unlocker } => {
				self.transactional_process(|self_ref| {
					let origin = self_ref.cloned_origin().ok_or(XcmError::BadOrigin)?;
					let (remote_asset, context) = Self::try_reanchor(asset.clone(), &unlocker)?;
					let lock_ticket =
						Config::AssetLocker::prepare_lock(unlocker.clone(), asset, origin.clone())?;
					let owner = origin.reanchored(&unlocker, &context).map_err(|e| {
						tracing::error!(target: "xcm::xcm_executor::process_instruction", ?e, ?unlocker, ?context, "Failed to re-anchor origin");
						XcmError::ReanchorFailed
					})?;
					let msg = Xcm::<()>(vec![NoteUnlockable { asset: remote_asset, owner }]);
					let (ticket, price) = validate_send::<Config::XcmSender>(unlocker, msg)?;
					self_ref.take_fee(price, FeeReason::LockAsset)?;
					lock_ticket.enact()?;
					Config::XcmSender::deliver(ticket)?;
					Ok(())
				})
```

**File:** polkadot/xcm/xcm-executor/src/lib.rs (L1726-1753)
```rust
			UnlockAsset { asset, target } => {
				let origin = self.cloned_origin().ok_or(XcmError::BadOrigin)?;
				Config::AssetLocker::prepare_unlock(origin, asset, target)?.enact()?;
				Ok(())
			},
			NoteUnlockable { asset, owner } => {
				let origin = self.cloned_origin().ok_or(XcmError::BadOrigin)?;
				Config::AssetLocker::note_unlockable(origin, asset, owner)?;
				Ok(())
			},
			RequestUnlock { asset, locker } => {
				let origin = self.cloned_origin().ok_or(XcmError::BadOrigin)?;
				let remote_asset = Self::try_reanchor(asset.clone(), &locker)?.0;
				let remote_target = Self::try_reanchor(origin.clone(), &locker)?.0;
				let reduce_ticket = Config::AssetLocker::prepare_reduce_unlockable(
					locker.clone(),
					asset,
					origin.clone(),
				)?;
				let msg =
					Xcm::<()>(vec![UnlockAsset { asset: remote_asset, target: remote_target }]);
				let (ticket, price) = validate_send::<Config::XcmSender>(locker, msg)?;
				self.transactional_process(|self_ref| {
					self_ref.take_fee(price, FeeReason::RequestUnlock)?;
					reduce_ticket.enact()?;
					Config::XcmSender::deliver(ticket)?;
					Ok(())
				})
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L3675-3712)
```rust
pub struct LockTicket<T: Config> {
	sovereign_account: T::AccountId,
	amount: BalanceOf<T>,
	unlocker: Location,
	item_index: Option<usize>,
}

impl<T: Config> xcm_executor::traits::Enact for LockTicket<T> {
	fn enact(self) -> Result<(), xcm_executor::traits::LockError> {
		use xcm_executor::traits::LockError::UnexpectedState;
		let mut locks = LockedFungibles::<T>::get(&self.sovereign_account).unwrap_or_default();
		match self.item_index {
			Some(index) => {
				ensure!(locks.len() > index, UnexpectedState);
				ensure!(locks[index].1.try_as::<_>() == Ok(&self.unlocker), UnexpectedState);
				locks[index].0 = locks[index].0.max(self.amount);
			},
			None => {
				locks.try_push((self.amount, self.unlocker.into())).map_err(
					|(balance, location)| {
						tracing::debug!(
							target: "xcm::pallet_xcm::enact", ?balance, ?location,
							"Failed to lock fungibles",
						);
						UnexpectedState
					},
				)?;
			},
		}
		LockedFungibles::<T>::insert(&self.sovereign_account, locks);
		T::Currency::extend_lock(
			*b"py/xcmlk",
			&self.sovereign_account,
			self.amount,
			WithdrawReasons::all(),
		);
		Ok(())
	}
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L3715-3749)
```rust
pub struct UnlockTicket<T: Config> {
	sovereign_account: T::AccountId,
	amount: BalanceOf<T>,
	unlocker: Location,
}

impl<T: Config> xcm_executor::traits::Enact for UnlockTicket<T> {
	fn enact(self) -> Result<(), xcm_executor::traits::LockError> {
		use xcm_executor::traits::LockError::UnexpectedState;
		let mut locks =
			LockedFungibles::<T>::get(&self.sovereign_account).ok_or(UnexpectedState)?;
		let mut maybe_remove_index = None;
		let mut locked = BalanceOf::<T>::zero();
		let mut found = false;
		// We could just as well do with an into_iter, filter_map and collect, however this way
		// avoids making an allocation.
		for (i, x) in locks.iter_mut().enumerate() {
			if x.1.try_as::<_>().defensive() == Ok(&self.unlocker) {
				x.0 = x.0.saturating_sub(self.amount);
				if x.0.is_zero() {
					maybe_remove_index = Some(i);
				}
				found = true;
			}
			locked = locked.max(x.0);
		}
		ensure!(found, UnexpectedState);
		if let Some(remove_index) = maybe_remove_index {
			locks.swap_remove(remove_index);
		}
		LockedFungibles::<T>::insert(&self.sovereign_account, locks);
		let reasons = WithdrawReasons::all();
		T::Currency::set_lock(*b"py/xcmlk", &self.sovereign_account, locked, reasons);
		Ok(())
	}
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L3840-3866)
```rust
	fn prepare_reduce_unlockable(
		locker: Location,
		asset: Asset,
		mut owner: Location,
	) -> Result<Self::ReduceTicket, xcm_executor::traits::LockError> {
		use xcm_executor::traits::LockError::*;
		let amount = match asset.fun {
			Fungible(a) => a,
			NonFungible(_) => return Err(Unimplemented),
		};
		owner.remove_network_id();
		let sovereign_account = T::SovereignAccountOf::convert_location(&owner).ok_or(BadOwner)?;
		let locker = locker.into();
		let owner = owner.into();
		let id: VersionedAssetId = asset.id.into();
		let key = (XCM_VERSION, sovereign_account, id);

		let record = RemoteLockedFungibles::<T>::get(&key).ok_or(NotLocked)?;
		// Make sure that the record contains what we expect and there's enough to unlock.
		ensure!(locker == record.locker && owner == record.owner, WouldClobber);
		ensure!(record.amount >= amount, NotEnoughLocked);
		ensure!(
			record.amount_held().map_or(true, |h| record.amount.saturating_sub(amount) >= h),
			InUse
		);
		Ok(ReduceTicket { key, amount, locker, owner })
	}
```
