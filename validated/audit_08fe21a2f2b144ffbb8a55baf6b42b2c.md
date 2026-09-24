### Title
Replayable identity/alias-setup proofs allow indefinite reversion of `pallet_people` account bindings within the tolerance window - ([File: substrate/frame/people/src/extension.rs])

### Summary
The Serenity advisory's core flaw is that a one-time authorization token (password-reset link) is not invalidated after it accomplishes its purpose, and remains valid for reuse (3-hour window) so any party who observed it (e.g., via browser history) can replay it to force a state change again. The `pallet_people` `AsPerson` transaction extension has the same class of flaw: the cryptographic proof/signature that authorizes `set_alias_account` / `set_personal_id_account` is not invalidated once consumed. It stays "live" for `account_setup_time_tolerance` blocks after `call_valid_at`, and the extension's own replay check only rejects an *exact repeat of the same resulting mapping* — not reuse of the token to reassert stale state. Any observer of a previously broadcast/finalized extrinsic (which is public on-chain data, unlike a private email link) can resubmit it and force the identity/alias binding back to the old value, as long as the tolerance window for that old, valid-at-timestamp signature has not elapsed.

### Finding Description
`AsPersonInfo::AsPersonalAliasWithProof` and `AsPersonInfo::AsPersonalIdentityWithProof` allow an unsigned (`Origin::None`) extrinsic to be authorized purely by a VRF proof / signature over `(EXTENSION_VERSION, call, other_tx_ext)`, checked in `TransactionExtension::validate`: [1](#0-0) [2](#0-1) 

The only replay protection is a comparison against the *currently stored* mapping:
```
// This protects again replay attack.
if AccountToAlias::<T>::get(account).is_some_and(|stored| stored == rev_ca) {
    return Err(InvalidTransaction::Stale.into());
}
```
This rejects only a no-op replay (setting the account to what it already is). It does **not** invalidate the *token* (proof/signature) itself. The enum's own doc comments admit this directly: [3](#0-2) 

As long as `now <= call_valid_at + account_setup_time_tolerance`, the exact same signed message can be resubmitted over and over to toggle the mapping back to a prior value, exactly analogous to a password-reset token that is still accepted after having already been used to change the password once.

The runtime test suite demonstrates this explicitly: after Alice sets `account=10` then `account=11`, replaying the *original* (already-consumed) transaction is accepted again — "It is within time tolerance" — flipping the binding back to 10, and this can be done repeatedly: [4](#0-3) [5](#0-4) 

### Impact Explanation
`AccountToPersonalId` / `AccountToAlias` / `AliasToAccount` bind an on-chain account to a personhood/identity or a contextual alias — security-relevant state used to gate personhood-restricted actions. Because the underlying proof/signature is not single-use, any account owner's own previously-broadcast (and hence publicly visible in the chain history) setup transaction can be replayed by *anyone* — not just the original signer — to unilaterally revert the account binding to a stale value within the tolerance window, undoing a legitimate account-holder's intentional migration (e.g., moving personhood recognition off a compromised or deprecated account). This is a state-integrity break stemming directly from failure to invalidate the authorization token after use, matching the CWE-640 pattern in the reference advisory, though the blast radius here is limited to `pallet_people` identity/alias bindings rather than fund custody, and the window is bounded by `account_setup_time_tolerance`.

### Likelihood Explanation
Reachable with no privileged role: the call path is `Origin::None` plus a proof/signature check, so no signing key beyond the original transaction's is required to replay it — an attacker only needs to observe/store any previously submitted `set_alias_account`/`set_personal_id_account` extrinsic (trivial, since blockchain data is public, unlike a private password-reset email). The window is bounded by `account_setup_time_tolerance`, which reduces but does not eliminate the exposure; likelihood is moderate given exploitation requires timing the replay before the tolerance window that expires, and the `pallet_people` pallet is not yet broadly deployed on mainnet chains.

### Recommendation
Bind replay protection to the token itself rather than only to the resulting mapping equality: e.g., include a strictly monotonic setup-nonce/generation counter per account/identity in the signed message and require any replay to prove nonce > last-used nonce (mirroring `CheckNonce`), or record and reject the exact `(account, call_valid_at, rev_ca/signature)` tuple once consumed regardless of what value it currently maps to. This prevents any consumed proof from being reused to force a prior state, closing the "insufficient token expiration" gap while preserving the legitimate use case of tolerating minor clock skew.

### Proof of Concept
The existing unit tests are the demonstrable reproduction through the real transaction-extension boundary (no mocks of the crypto/proof acceptance):
- `replay_protection_for_identity` (`substrate/frame/people/src/tests.rs:2833-2904`) shows `exec_tx` accepting the *same, already-applied* signed `set_personal_id_account` transaction a second and third time, flipping `AccountToPersonalId` back and forth between `10` and `11`, before finally rejecting it only once time tolerance is exceeded.
- `replay_protection_for_alias` (`substrate/frame/people/src/tests.rs:2905-2991`) shows the identical pattern for `set_alias_account`/`AccountToAlias`/`AliasToAccount`.

These tests currently assert the replay *succeeds* ("Replay the transaction... it must succeed. It is within time tolerance"), confirming the token-reuse behavior is real and exercised through the production `validate`/`prepare` path, not a mock. No PoC was executed against a live network; the analysis is based on the existing passing test assertions and source review, and is presented as a design-limitation finding acknowledged partially in code comments — reviewers should confirm intended severity classification against `pallet_people`'s current deployment status before treating this as bounty-eligible.

### Citations

**File:** substrate/frame/people/src/extension.rs (L44-63)
```rust
	/// The none origin will be transformed using proof.
	///
	/// This can only dispatch the call `set_alias_account`.
	///
	/// Replay is only protected against resetting the same account during the tolerance period
	/// after `call_valid_at` parameter.
	/// If 2 transaction that set 2 different account are sent for an overlapping validity period,
	/// then those 2 transactions can be replayed indefinitely for the duration of the overlapping
	/// period.
	AsPersonalAliasWithProof(<T::Crypto as GenerateVerifiable>::Proof, RingIndex, Context),
	/// The none origin will be transformed using signature.
	///
	/// This can only dispatch the call `set_personal_id_account`.
	///
	/// Replay is only protected against resetting the same account during the tolerance period
	/// after `call_valid_at` parameter.
	/// If 2 transaction that set 2 different account are sent for an overlapping validity period,
	/// then those 2 transactions can be replayed indefinitely for the duration of the overlapping
	/// period.
	AsPersonalIdentityWithProof(<T::Crypto as GenerateVerifiable>::Signature, PersonalId),
```

**File:** substrate/frame/people/src/extension.rs (L191-230)
```rust
			Some(AsPersonInfo::AsPersonalAliasWithProof(proof, ring_index, context)) => {
				ensure!(
					matches!(origin.as_system_ref(), Some(frame_system::RawOrigin::None)),
					InvalidTransaction::BadSigner
				);

				let Some(Call::<T>::set_alias_account { account, call_valid_at }) =
					call.is_sub_type()
				else {
					return Err(InvalidTransaction::Call.into());
				};

				let ring = Root::<T>::get(ring_index).ok_or(InvalidTransaction::Call)?;
				let now = frame_system::Pallet::<T>::block_number();
				if now < *call_valid_at {
					return Err(InvalidTransaction::Future.into());
				}
				let time_tolerance = Pallet::<T>::account_setup_time_tolerance();
				if now > call_valid_at.saturating_add(time_tolerance) {
					return Err(InvalidTransaction::Stale.into());
				}

				let msg = inherited_implication.using_encoded(sp_io::hashing::blake2_256);

				let alias = T::Crypto::validate(proof, &ring.root, &context[..], &msg[..])
					.map_err(|_| InvalidTransaction::BadProof)?;

				let rev_ca = RevisedContextualAlias {
					revision: ring.revision,
					ring: *ring_index,
					ca: ContextualAlias { alias, context: *context },
				};

				// This protects again replay attack.
				if AccountToAlias::<T>::get(account)
					.is_some_and(|stored_rev_ca| stored_rev_ca == rev_ca)
				{
					return Err(InvalidTransaction::Stale.into());
				}

```

**File:** substrate/frame/people/src/extension.rs (L243-279)
```rust
			Some(AsPersonInfo::AsPersonalIdentityWithProof(signature, index)) => {
				ensure!(
					matches!(origin.as_system_ref(), Some(frame_system::RawOrigin::None)),
					InvalidTransaction::BadSigner
				);

				let Some(Call::<T>::set_personal_id_account { account, call_valid_at }) =
					call.is_sub_type()
				else {
					return Err(InvalidTransaction::Call.into());
				};

				let now = frame_system::Pallet::<T>::block_number();
				if now < *call_valid_at {
					return Err(InvalidTransaction::Future.into());
				}
				let time_tolerance = Pallet::<T>::account_setup_time_tolerance();
				if now > call_valid_at.saturating_add(time_tolerance) {
					return Err(InvalidTransaction::Stale.into());
				}

				let key = People::<T>::get(index)
					.map(|record| record.key)
					.ok_or(InvalidTransaction::BadSigner)?;

				let msg = inherited_implication.using_encoded(sp_io::hashing::blake2_256);

				if !T::Crypto::verify_signature(signature, &msg[..], &key) {
					return Err(InvalidTransaction::BadProof.into());
				}

				// This protects again replay attack.
				if People::<T>::get(index).is_some_and(|record| {
					record.account.is_some_and(|stored_account| stored_account == *account)
				}) {
					return Err(InvalidTransaction::Stale.into());
				}
```

**File:** substrate/frame/people/src/tests.rs (L2879-2903)
```rust
		// Advance some time. Transaction 1 is still valid, transaction 2 becomes valid.
		mock::advance_to(System::block_number() + PeoplePallet::account_setup_time_tolerance());
		// Transaction 2 is now valid.
		assert_ok!(exec_tx(None, tx_ext_2.clone(), call_2.clone()));
		assert_eq!(crate::People::<Test>::get(alice_index).unwrap().account, Some(11));
		assert_eq!(crate::AccountToPersonalId::<Test>::get(11), Some(alice_index));
		assert_eq!(crate::AccountToPersonalId::<Test>::get(10), None);
		// Somebody replays the transaction 1, it must succeed. It is within time tolerance.
		assert_ok!(exec_tx(None, tx_ext.clone(), call.clone()));
		assert_eq!(crate::People::<Test>::get(alice_index).unwrap().account, Some(10));
		assert_eq!(crate::AccountToPersonalId::<Test>::get(10), Some(alice_index));
		assert_eq!(crate::AccountToPersonalId::<Test>::get(11), None);
		// Replay the transaction 2.
		assert_ok!(exec_tx(None, tx_ext_2.clone(), call_2.clone()));
		assert_eq!(crate::People::<Test>::get(alice_index).unwrap().account, Some(11));
		assert_eq!(crate::AccountToPersonalId::<Test>::get(11), Some(alice_index));
		assert_eq!(crate::AccountToPersonalId::<Test>::get(10), None);
		// Advance some time, Now time tolerance is exceeded for transaction 1.
		mock::advance_to(System::block_number() + 1);
		// Somebody replays the first transaction, it is invalid.
		assert_noop!(exec_tx(None, tx_ext, call), InvalidTransaction::Stale);
		assert_eq!(crate::People::<Test>::get(alice_index).unwrap().account, Some(11));
		assert_eq!(crate::AccountToPersonalId::<Test>::get(11), Some(alice_index));
		assert_eq!(crate::AccountToPersonalId::<Test>::get(10), None);
	});
```

**File:** substrate/frame/people/src/tests.rs (L2938-2990)
```rust
		// --- Transaction 1: set alias account to 10 ---
		// Use the current block number as the valid time.
		let call1 = RuntimeCall::PeoplePallet(crate::Call::set_alias_account {
			account: 10,
			call_valid_at: System::block_number(),
		});
		let (tx_ext1, alias) = generate_alias_tx_ext_for_call(call1.clone());
		let rev_alias = RevisedContextualAlias { revision: 0, ring: 0, ca: alias.clone() };
		// Execute transaction 1. It should succeed.
		assert_ok!(exec_tx(None, tx_ext1.clone(), call1.clone()));
		assert_eq!(crate::AliasToAccount::<Test>::get(&alias), Some(10));
		assert_eq!(crate::AccountToAlias::<Test>::get(10), Some(rev_alias.clone()));
		// Replay transaction 1 immediately: it must fail (replay protected).
		assert_noop!(exec_tx(None, tx_ext1.clone(), call1.clone()), InvalidTransaction::Stale);
		// --- Transaction 2: set alias account to 11 ---
		// Set its valid time to the future: current block number plus the allowed tolerance + 1.
		let call2 = RuntimeCall::PeoplePallet(crate::Call::set_alias_account {
			account: 11,
			call_valid_at: System::block_number() + 1,
		});
		let (tx_ext2, _) = generate_alias_tx_ext_for_call(call2.clone());
		// Transaction 2 is too early: it should be rejected as "Future".
		assert_noop!(exec_tx(None, tx_ext2.clone(), call2.clone()), InvalidTransaction::Future);
		// The mapping still reflects transaction 1.
		assert_eq!(crate::AliasToAccount::<Test>::get(&alias), Some(10));
		assert_eq!(crate::AccountToAlias::<Test>::get(10), Some(rev_alias.clone()));
		assert_eq!(crate::AccountToAlias::<Test>::get(11), None);
		// Advance time by the allowed tolerance. Now transaction 2 becomes valid.
		mock::advance_to(System::block_number() + PeoplePallet::account_setup_time_tolerance());
		// Execute transaction 2. It now succeeds.
		assert_ok!(exec_tx(None, tx_ext2.clone(), call2.clone()));
		assert_eq!(crate::AliasToAccount::<Test>::get(&alias), Some(11));
		assert_eq!(crate::AccountToAlias::<Test>::get(11), Some(rev_alias.clone()));
		assert_eq!(crate::AccountToAlias::<Test>::get(10), None);
		// --- Replaying old transactions within tolerance ---
		// Replay transaction 1. Within the tolerance window its replay is allowed.
		assert_ok!(exec_tx(None, tx_ext1.clone(), call1.clone()));
		assert_eq!(crate::AliasToAccount::<Test>::get(&alias), Some(10));
		assert_eq!(crate::AccountToAlias::<Test>::get(10), Some(rev_alias.clone()));
		assert_eq!(crate::AccountToAlias::<Test>::get(11), None);
		// Replay transaction 2 to set it back to 11.
		assert_ok!(exec_tx(None, tx_ext2.clone(), call2.clone()));
		assert_eq!(crate::AliasToAccount::<Test>::get(&alias), Some(11));
		assert_eq!(crate::AccountToAlias::<Test>::get(11), Some(rev_alias.clone()));
		assert_eq!(crate::AccountToAlias::<Test>::get(10), None);
		// --- Advance time beyond tolerance ---
		// After advancing time a bit more, the time tolerance for transaction 1 is exceeded.
		mock::advance_to(System::block_number() + 1);
		// Now replaying transaction 1 must be rejected as stale.
		assert_noop!(exec_tx(None, tx_ext1, call1), InvalidTransaction::Stale);
		assert_eq!(crate::AliasToAccount::<Test>::get(&alias), Some(11));
		assert_eq!(crate::AccountToAlias::<Test>::get(11), Some(rev_alias));
	});
```
