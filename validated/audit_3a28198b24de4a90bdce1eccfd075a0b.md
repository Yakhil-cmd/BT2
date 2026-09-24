Confirmed: `do_set_keys` and `do_purge_keys` (called by the `set_keys`/`purge_keys` extrinsics) mutate `NextKeys`, `KeyOwner`, `ExternallySetKeys`, place/release currency holds, and increment/decrement consumer refs — but neither path calls `Self::deposit_event(...)` anywhere. The pallet's `Event<T>` enum only defines `NewSession`, `NewQueued`, `ValidatorDisabled`, `ValidatorReenabled` — none of which fire on a successful key change.

### Title
`pallet-session::set_keys`/`purge_keys` perform validator credential changes without emitting any audit event - ([File: substrate/frame/session/src/lib.rs])

### Summary
`pallet-session`'s `set_keys` and `purge_keys` extrinsics let any signed account (converted to a `ValidatorId`) register, rotate, or remove the session keys that authorize block/finality production. Unlike essentially every other sensitive state mutation in FRAME (e.g. `pallet-proxy`'s `ProxyAdded`/`ProxyRemoved`, or `pallet-staking-async-ah-client`'s `SessionKeysUpdated`/`SessionKeysUpdateFailed`), these calls complete silently: no `Event` is deposited on success or failure.

### Finding Description
The extrinsics `set_keys` and `purge_keys` at [1](#0-0)  call `do_set_keys`/`do_purge_keys`, which mutate `NextKeys`, `KeyOwner`, `ExternallySetKeys`, place/release a `KeyDeposit` hold, and inc/dec the consumer ref count [2](#0-1) , [3](#0-2) . None of these code paths call `Self::deposit_event`. The pallet's declared `Event<T>` enum only contains `NewSession`, `NewQueued`, `ValidatorDisabled`, `ValidatorReenabled` [4](#0-3)  — there is no `KeysSet`/`KeysPurged`-style event.

This mirrors the OpenEMR bug class precisely: the state change is genuinely persisted (analogous to the DB write in OpenEMR), but the action that changes a security-critical credential (session keys are the "password" that authorizes a stash/controller to sign blocks as a validator) is not recorded on the observable audit trail (the chain's event log, which is what indexers, explorers, and monitoring tooling consume — analogous to OpenEMR's "client-side log viewer"). Anyone who wants to audit "when did this validator's keys change" cannot do so via events; they must brute-force diff storage across every block, which most monitoring/indexing infrastructure does not do.

Notably, the newer `pallet-staking-async-ah-client` explicitly fixed this exact gap for the AssetHub-forwarded path by adding `SessionKeysUpdated`/`SessionKeysUpdateFailed` events [5](#0-4) , and a prdoc documents this as a deliberate observability improvement [6](#0-5) . This confirms the project itself treats missing session-key-change events as an observability defect worth fixing — but the original, directly-signed `pallet_session::set_keys`/`purge_keys` path (still supported and used by relay chains/parachains not on staking-async) remains unfixed.

### Impact Explanation
This is a low-severity observability/auditability weakness, not a fund-loss or consensus-safety bug. It matches the CVSS profile of the OpenEMR analog (no confidentiality/availability impact, low integrity impact via reduced traceability). Concretely: a validator's session keys could be rotated or purged (e.g., by a compromised controller account, or as part of a social-engineering/insider scenario) with no on-chain event for downstream monitoring, alerting, or block explorers to flag, delaying detection of unauthorized key changes.

### Likelihood Explanation
High likelihood of the underlying condition being present (it is unconditional — the code simply never emits an event), but low likelihood of being exploited for meaningful attacker gain, since the state itself (`NextKeys`, `KeyOwner`) is still correctly recorded and queryable; the issue only affects passive/event-driven monitoring, not the ability to detect misuse via direct storage inspection.

### Recommendation
Add `deposit_event` calls in `do_set_keys`/`do_purge_keys` (or in the `set_keys`/`purge_keys` extrinsics) analogous to the `SessionKeysUpdated`/`SessionKeysUpdateFailed` events already added in `pallet-staking-async-ah-client`, so that key registration, rotation, and purge are all observable via the standard event log.

### Proof of Concept
No dynamic PoC was executed (static code review only). Evidence is the absence of any `deposit_event` invocation in `set_keys`/`purge_keys`/`do_set_keys`/`do_purge_keys`/`inner_set_keys` in `substrate/frame/session/src/lib.rs`, confirmed by reading the full call chain and the `Event<T>` enum definition, contrasted with the sibling pallet `pallet-staking-async-ah-client` which does emit corresponding events for the same logical operation forwarded from AssetHub [7](#0-6) . Existing unit tests (`substrate/frame/session/src/tests.rs`) assert on storage/hold changes after `set_keys`/`purge_keys` but never assert on any emitted event, further corroborating that none exists [8](#0-7) .

### Citations

**File:** substrate/frame/session/src/lib.rs (L637-650)
```rust
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// New session has happened. Note that the argument is the session index, not the
		/// block number as the type might suggest.
		NewSession { session_index: SessionIndex },
		/// The `NewSession` event in the current block also implies a new validator set to be
		/// queued.
		NewQueued,
		/// Validator has been disabled.
		ValidatorDisabled { validator: T::ValidatorId },
		/// Validator has been re-enabled.
		ValidatorReenabled { validator: T::ValidatorId },
	}
```

**File:** substrate/frame/session/src/lib.rs (L702-729)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::set_keys())]
		pub fn set_keys(origin: OriginFor<T>, keys: T::Keys, proof: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(
				who.using_encoded(|who| keys.ownership_proof_is_valid(who, &proof)),
				Error::<T>::InvalidProof,
			);

			Self::do_set_keys(&who, keys)?;
			Ok(())
		}

		/// Removes any session key(s) of the function caller.
		///
		/// This doesn't take effect until the next session.
		///
		/// The dispatch origin of this function must be Signed and the account must be either be
		/// convertible to a validator ID using the chain's typical addressing system (this usually
		/// means being a controller account) or directly convertible into a validator ID (which
		/// usually means being a stash account).
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::purge_keys())]
		pub fn purge_keys(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::do_purge_keys(&who)?;
			Ok(())
		}
```

**File:** substrate/frame/session/src/lib.rs (L956-994)
```rust
	/// Perform the set_key operation, checking for duplicates. Does not set `Changed`.
	///
	/// The old keys for this validator are returned, or `None` if there were none.
	///
	/// This does not ensure that the reference counter in system is incremented appropriately, it
	/// must be done by the caller or the keys will be leaked in storage.
	fn inner_set_keys(
		who: &T::ValidatorId,
		keys: T::Keys,
	) -> Result<Option<T::Keys>, DispatchError> {
		let old_keys = Self::load_keys(who);

		for id in T::Keys::key_ids() {
			let key = keys.get_raw(*id);

			// ensure keys are without duplication.
			ensure!(
				Self::key_owner(*id, key).map_or(true, |owner| &owner == who),
				Error::<T>::DuplicatedKey,
			);
		}

		for id in T::Keys::key_ids() {
			let key = keys.get_raw(*id);

			if let Some(old) = old_keys.as_ref().map(|k| k.get_raw(*id)) {
				if key == old {
					continue;
				}

				Self::clear_key_owner(*id, old);
			}

			Self::put_key_owner(*id, key, who);
		}

		Self::put_keys(who, &keys);
		Ok(old_keys)
	}
```

**File:** substrate/frame/session/src/lib.rs (L996-1023)
```rust
	fn do_purge_keys(account: &T::AccountId) -> DispatchResult {
		let who = T::ValidatorIdOf::convert(account.clone())
			// `purge_keys` may not have a controller-stash pair any more. If so then we expect the
			// stash account to be passed in directly and convert that to a `ValidatorId` using the
			// `TryFrom` trait if supported.
			.or_else(|| T::ValidatorId::try_from(account.clone()).ok())
			.ok_or(Error::<T>::NoAssociatedValidatorId)?;

		let old_keys = Self::take_keys(&who).ok_or(Error::<T>::NoKeys)?;
		for id in T::Keys::key_ids() {
			let key_data = old_keys.get_raw(*id);
			Self::clear_key_owner(*id, key_data);
		}

		// Use release_all to handle the case where the exact amount might not be available
		let _ = T::Currency::release_all(
			&HoldReason::Keys.into(),
			account,
			frame_support::traits::tokens::Precision::BestEffort,
		);

		if ExternallySetKeys::<T>::take(account).is_none() {
			// Consumer was incremented locally via `do_set_keys`, so decrement it.
			frame_system::Pallet::<T>::dec_consumers(account);
		}

		Ok(())
	}
```

**File:** substrate/frame/staking-async/ah-client/src/lib.rs (L469-477)
```rust
		/// Session keys updated for a validator.
		SessionKeysUpdated { stash: T::AccountId, update: SessionKeysUpdate },
		/// Session key update from AssetHub failed on the relay chain.
		/// Logged as an event for fail-safe observability.
		SessionKeysUpdateFailed {
			stash: T::AccountId,
			update: SessionKeysUpdate,
			error: DispatchError,
		},
```

**File:** substrate/frame/staking-async/ah-client/src/lib.rs (L641-700)
```rust
		/// Set session keys for a validator, forwarded from AssetHub.
		///
		/// This is called when a validator sets their session keys on AssetHub, which forwards
		/// the request to the RelayChain via XCM.
		///
		/// AssetHub validates both keys and ownership proof before sending.
		/// RC trusts AH's validation and does not re-validate.
		#[pallet::call_index(3)]
		#[pallet::weight(T::SessionInterface::set_keys_weight())]
		pub fn set_keys_from_ah(
			origin: OriginFor<T>,
			stash: T::AccountId,
			keys: Vec<u8>,
		) -> DispatchResult {
			T::AssetHubOrigin::ensure_origin_or_root(origin)?;
			log::info!(target: LOG_TARGET, "Received set_keys request from AssetHub for {stash:?}");

			// Decode the keys from bytes (AH already validated, this is just for type conversion)
			let session_keys =
				match <<T as Config>::SessionInterface as SessionInterface>::Keys::decode(
					&mut &keys[..],
				) {
					Ok(keys) => keys,
					Err(e) => {
						// This should never happen since AH validates keys before forwarding.
						// Returning Ok() allows the event to be observed for monitoring.
						log!(
							warn,
							"InvalidKeysFromAssetHub: failed to decode keys for {:?}: {:?}",
							stash,
							e
						);
						Self::deposit_event(Event::Unexpected(
							UnexpectedKind::InvalidKeysFromAssetHub,
						));
						return Ok(());
					},
				};

			match T::SessionInterface::set_keys(&stash, session_keys) {
				Ok(()) => Self::deposit_event(Event::SessionKeysUpdated {
					stash,
					update: SessionKeysUpdate::Set,
				}),
				Err(error) => {
					log!(
						warn,
						"SessionKeysUpdateFailed: set_keys failed for {:?}: {:?}",
						stash,
						error
					);
					Self::deposit_event(Event::SessionKeysUpdateFailed {
						stash,
						update: SessionKeysUpdate::Set,
						error,
					});
				},
			}
			Ok(())
		}
```

**File:** prdoc/stable2512-2/pr_11055.prdoc (L1-9)
```text
title: 'staking-async/ah-client: emit event when session key update from AssettHub
  fails on relay chain'
doc:
- audience: Runtime Dev
  description: |-
    Emit SessionKeysUpdateFailed with the operation type and dispatch
    error for observability so set_keys/purge_kets failures from AssetHub are observable
    on-chain
crates:
```

**File:** substrate/frame/session/src/tests.rs (L536-601)
```rust
#[test]
fn set_keys_should_hold_funds() {
	new_test_ext().execute_with(|| {
		// Account 1000 is mocked to have sufficient funds
		let account_id = 1000;
		let keys = MockSessionKeys { dummy: UintAuthorityId(account_id).into() };
		let deposit = KeyDeposit::get();

		// Make sure we have a validator ID
		ValidatorAccounts::mutate(|m| {
			m.insert(account_id, account_id);
		});

		// Set keys and check the operation succeeds
		let res = Session::set_keys(
			RuntimeOrigin::signed(account_id),
			keys,
			create_set_keys_proof(account_id, &UintAuthorityId(account_id)),
		);
		assert_ok!(res);

		// Check that the funds are held
		assert_eq!(session_hold(account_id), deposit);
	});
}

#[test]
fn purge_keys_should_unhold_funds() {
	new_test_ext().execute_with(|| {
		// Account 1000 is mocked to have sufficient funds
		let account_id = 1000;
		let keys = MockSessionKeys { dummy: UintAuthorityId(account_id).into() };
		let deposit = KeyDeposit::get();

		// Make sure we have a validator ID
		ValidatorAccounts::mutate(|m| {
			m.insert(account_id, account_id);
		});

		// Ensure system providers are properly set for the test account
		frame_system::Pallet::<Test>::inc_providers(&account_id);

		// First set the keys to reserve the deposit
		let res = Session::set_keys(
			RuntimeOrigin::signed(account_id),
			keys,
			create_set_keys_proof(account_id, &UintAuthorityId(account_id)),
		);
		assert_ok!(res);

		// Check the reserved balance after setting keys
		let reserved_balance_before_purge = Balances::reserved_balance(&account_id);
		assert!(
			reserved_balance_before_purge >= deposit,
			"Deposit should be reserved after setting keys"
		);

		// Now purge the keys
		let res = Session::purge_keys(RuntimeOrigin::signed(account_id));
		assert_ok!(res);

		// Check that the funds were unreserved
		let reserved_balance_after_purge = Balances::reserved_balance(&account_id);
		assert_eq!(reserved_balance_after_purge, reserved_balance_before_purge - deposit);
	});
}
```
