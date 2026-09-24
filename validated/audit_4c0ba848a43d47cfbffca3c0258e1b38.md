## Analog Found: Permanent Asset Lock via Unacknowledged Cross-Chain `LockAsset`/`NoteUnlockable` XCM Instructions

### Title
Asset permanently locked via `LockAsset` XCM instruction whose fee validation only covers message delivery, not guaranteed remote execution of `NoteUnlockable` - ([File: polkadot/xcm/xcm-executor/src/lib.rs])

### Summary
`pallet_xcm::execute` lets any signed, filtered origin submit an XCM program containing the `LockAsset` instruction. The executor's handling of `LockAsset` [1](#0-0)  validates and charges only the *delivery* fee for the outbound `NoteUnlockable` notification (`validate_send` + `take_fee`), then unconditionally enacts the local lock (`lock_ticket.enact()?`) before firing the message off with `Config::XcmSender::deliver(ticket)`. There is no accounting for whether the destination (`unlocker`) chain will actually be able to execute the `NoteUnlockable` instruction (its own weight/fee/Barrier requirements) — the exact analog of the TON report's missing `TON_reserve_amount`. If that remote execution fails or is dropped, the local asset remains locked forever with no way to reach `UnlockAsset`, because the only unlock path (`RequestUnlock`) requires the destination to already hold a `RemoteLockedFungibleRecord`, which is only created by a successfully executed `NoteUnlockable`.

### Finding Description
The `LockAsset` instruction handler: [1](#0-0) 

only validates the **delivery price** of the outbound message via `validate_send`, charges that price with `take_fee`, and then calls `lock_ticket.enact()` — which for the reference `pallet-xcm` implementation immediately mutates local storage (`LockedFungibles`) and issues an actual `Currency::set_lock` on the owner's sovereign account: [2](#0-1) 

The lock is enacted unconditionally as soon as delivery is *accepted into the queue* (`XcmSender::deliver` returning `Ok`), regardless of whether the `unlocker` chain will ever actually process the `NoteUnlockable` instruction it receives. Execution of `NoteUnlockable` on the remote chain is subject to that chain's own `Barrier` (e.g. `AllowUnpaidExecutionFrom`) and weight limits — none of which the sender chain validates or reserves for. This mirrors the TON bug precisely: fee validation covers only the "enough_fee" (delivery) portion, not the "TON_reserve_amount" (remote completion) portion.

The trait's own documentation for `note_unlockable` even states the assumption that is violated: [3](#0-2) 
"If there is no way to handle the lock report, then this should return an error so that the sending chain can ensure the lock does not remain." But because `NoteUnlockable` is delivered as a one-way, fire-and-forget XCM message (no synchronous reply, no `QueryResponse` wiring in the `LockAsset` handler), the sending chain has **no mechanism whatsoever** to learn that the remote processing failed, and therefore cannot "ensure the lock does not remain" as the documentation promises.

Unlocking is only possible via `RequestUnlock`, which requires the destination to already have recorded a `RemoteLockedFungibleRecord` for the exact `(locker, owner, asset)` key: [4](#0-3) 
If `note_unlockable` never ran on the unlocker (barrier rejection, insufficient weight, message dropped/trapped, version incompatibility, etc.), this record never exists, `prepare_reduce_unlockable` always returns `LockError::NotLocked`, and the owner can never send a valid `UnlockAsset` back to the locker. The `LockedFungibles` entry and the underlying `Currency::set_lock` on the locker chain persist indefinitely.

### Impact Explanation
This is an irreversible freezing of user funds bug class (matching the report's "user contract state lock"): an ordinary user account, using a fully permitted extrinsic (`pallet_xcm::execute`) with no privileged role, can have its own — or, if a chain's `XcmExecuteFilter`/barriers allow constructing `LockAsset` with attacker-chosen `unlocker` targeting a misconfigured or incompatible remote chain, another origin's — assets locked with no available unlock path. Even in the benign self-inflicted case, this represents a deterministic irreversible fund-freezing defect reachable by normal users without any privileged prerequisite, matching High/Critical "irreversible freezing" criteria in the scan's own prioritization.

### Likelihood Explanation
Triggering requires only: (1) a runtime that permits `pallet_xcm::execute` for signed origins with a filter that does not exclude `LockAsset` (this is the default/common configuration used in the xcm-simulator examples we found, e.g. `polkadot/xcm/xcm-simulator/example/src/tests.rs` `remote_locking_and_unlocking` test), and (2) the chosen `unlocker` destination either lacking an `AllowUnpaidExecutionFrom`-style barrier for the sender, having insufficient configured weight, or otherwise being unable/unwilling to execute an unpaid, un-fee-bought `NoteUnlockable` instruction (which carries no `BuyExecution`). Both conditions are plausible in real multi-chain deployments where the `unlocker` is a third-party or not specifically configured to trust unpaid inbound `NoteUnlockable` from the locker.

### Recommendation
- Do not enact the local lock (`lock_ticket.enact()`) purely on successful *delivery* of the `NoteUnlockable` message; require either a synchronous confirmation/reply mechanism (e.g. via `ReportError`/`QueryResponse`) before committing the lock, or provide a chain-local timeout/expiry and self-service unlock path if no confirmation is received within a bounded window.
- Alternatively, require the `NoteUnlockable` message to carry its own `BuyExecution`/fees so it is guaranteed processable rather than depending on unpaid-execution barriers on the destination, and validate that the destination is configured to accept it before enacting the local lock.
- Add integration tests that simulate `NoteUnlockable` being dropped/barrier-rejected on the destination and assert the local lock is either not enacted or is recoverable.

### Proof of Concept
No PoC was executed against a live network. The vulnerable code path was confirmed by static analysis and existing unit tests demonstrate the pieces of the mechanism (but not the failure-after-delivery gap, since existing tests only cover delivery-fee failures, which correctly abort atomically via `transactional_process` before `enact()` — the actual gap is *post-delivery, remote-execution* failure, which the existing test suite does not exercise): [5](#0-4) 
A minimal reproduction would extend `polkadot/xcm/xcm-simulator/example` to configure `ParaA` (the `unlocker`) to reject unpaid execution from `ParaB`/relay (e.g. remove it from `AllowUnpaidFrom` or reduce its weight budget below `NoteUnlockable`'s weight), then repeat the `remote_locking_and_unlocking` test's `LockAsset` step from `ParaB`, and assert that (a) `ParaB`'s local lock (`LockedFungibles`) is still present, and (b) a subsequent `RequestUnlock` from `ParaB` fails with `LockError::NotLocked` — demonstrating the asset is stuck with no recovery path. This was not executed in this session; it is proposed as the concrete integration test to confirm the finding.

### Citations

**File:** polkadot/xcm/xcm-executor/src/lib.rs (L1708-1725)
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
			},
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L3781-3794)
```rust
	fn prepare_lock(
		unlocker: Location,
		asset: Asset,
		owner: Location,
	) -> Result<LockTicket<T>, xcm_executor::traits::LockError> {
		use xcm_executor::traits::LockError::*;
		let sovereign_account = T::SovereignAccountOf::convert_location(&owner).ok_or(BadOwner)?;
		let amount = T::CurrencyMatcher::matches_fungible(&asset).ok_or(UnknownAsset)?;
		ensure!(T::Currency::free_balance(&sovereign_account) >= amount, AssetNotOwned);
		let locks = LockedFungibles::<T>::get(&sovereign_account).unwrap_or_default();
		let item_index = locks.iter().position(|x| x.1.try_as::<_>() == Ok(&unlocker));
		ensure!(item_index.is_some() || locks.len() < T::MaxLockers::get() as usize, NoResources);
		Ok(LockTicket { sovereign_account, amount, unlocker, item_index })
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

**File:** polkadot/xcm/xcm-executor/src/traits/asset_lock.rs (L99-106)
```rust
	/// Handler for when a location reports to us that an asset has been locked for us to unlock
	/// at a later stage.
	///
	/// If there is no way to handle the lock report, then this should return an error so that the
	/// sending chain can ensure the lock does not remain.
	///
	/// We should only act upon this message if we believe that the `origin` is honest.
	fn note_unlockable(locker: Location, asset: Asset, owner: Location) -> Result<(), LockError>;
```

**File:** polkadot/xcm/xcm-builder/src/tests/locking.rs (L103-160)
```rust
#[test]
fn lock_should_fail_correctly() {
	// Account #3 can execute for free
	AllowUnpaidFrom::set(vec![(3u64,).into(), (Parent, Parachain(1)).into()]);

	// #3 wants to lock 100 of the native parent tokens to be unlocked only by parachain ../#1,
	// but they don't have any.
	let message = Xcm(vec![LockAsset {
		asset: (Parent, 100u128).into(),
		unlocker: (Parent, Parachain(1)).into(),
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		(3u64,),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::LockError },
		}
	);
	assert_eq!(sent_xcm(), vec![]);
	assert_eq!(take_lock_trace(), vec![]);

	// Account #3 owns 1000 native parent tokens.
	add_asset((3u64,), (Parent, 1000u128));
	// But we require a price to be paid for the sending
	set_send_price((Parent, 10u128));

	// #3 wants to lock 100 of the native parent tokens to be unlocked only by parachain ../#1,
	// but there's nothing to pay the fees for sending the notification message.
	let message = Xcm(vec![LockAsset {
		asset: (Parent, 100u128).into(),
		unlocker: (Parent, Parachain(1)).into(),
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		(3u64,),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::NotHoldingFees },
		}
	);
	assert_eq!(sent_xcm(), vec![]);
	assert_eq!(take_lock_trace(), vec![]);
}
```
