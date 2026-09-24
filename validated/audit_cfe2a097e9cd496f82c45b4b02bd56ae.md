### Title
Collection team permissions (`Issuer`/`Admin`/`Freezer`) survive `pallet-nfts` collection ownership transfer, letting a previous owner retain control of items - (File: `substrate/frame/nfts/src/features/transfer.rs`)

### Summary
`pallet-nfts::transfer_ownership` (and its privileged counterpart `force_collection_owner`) change only the `Collection.owner` field. They never touch the `CollectionRoleOf` storage map that holds the `Issuer`/`Admin`/`Freezer` team roles. Any account that was granted one of these roles by the previous owner keeps it after the collection is handed to a new owner, mirroring the LSP6 "universal permission survives ownership transfer" pattern from the referenced report: permissions are bound to the collection, not to a specific owner epoch, so a malicious former owner (or an accomplice they appointed) can retain real control after giving up nominal ownership.

### Finding Description
`do_transfer_ownership` moves the owner-deposit, updates `Collection::owner`, `CollectionAccount`, and `OwnershipAcceptance`, but does not call `clear_roles` or otherwise touch `CollectionRoleOf`: [1](#0-0) 

The forced variant used by `ForceOrigin` has the exact same gap: [2](#0-1) 

Team roles are a completely separate storage item (`CollectionRoleOf`) managed only by `do_set_team`/`clear_roles`, called from the `set_team` extrinsic: [3](#0-2) 

The dispatchable-level doc comments for `transfer_ownership` confirm the only stated effect is a change of the `owner` field, with no mention that team roles are reset — exactly the kind of silent, unstated behavior flagged as the root cause in the referenced LSP6 finding ("it is impossible to know if some user has permissions set"): [4](#0-3) 

These roles are not cosmetic — they grant real operational power over items regardless of who currently owns the collection:
- `Freezer` can lock/unlock any item's transferability (`do_lock_item_transfer` / `do_unlock_item_transfer`), effectively soul-binding items chosen by the new owner without the new owner's consent: [5](#0-4) 
- `Admin` can lock item metadata/attributes (`do_lock_item_properties`) and, per the role's own documentation, can "thaw items, force transfers and burn items from any account": [6](#0-5) [7](#0-6) 
- `Issuer` can mint further items into the collection via pre-signed mints: [8](#0-7) 

Reachability: `create`, `set_team`, `transfer_ownership`, and `set_accept_ownership` are all permissionless/`Signed` extrinsics reachable by any account with no privileged role, exactly matching the "real user entry, no privileged prerequisite" requirement: [9](#0-8) 

### Impact Explanation
A collection creator can appoint themselves (or a colluding account) as `Admin`/`Freezer`/`Issuer` while they are the owner, then transfer the collection to an unsuspecting buyer/recipient via `transfer_ownership`. The recipient, believing they now fully control the collection, is unaware that the former owner's chosen team retains the ability to: freeze/unlock item transferability, lock item metadata/attributes, mint new items (Issuer, via pre-signed mint), and — per the `Admin` role's documented capability — thaw items, force-transfer items, and burn items from any account in the collection. This can be used to grief, "rug", or extract value from a new owner who reasonably assumes ownership transfer implies a clean handover, exactly the scenario judged Medium severity ("weak medium/strong analysis... eye-opening for the team... functionality is lacking") in the source report. Unlike the original LSP6 report, the new owner *can* self-remediate here (by calling `set_team` to overwrite the roles, since `set_team` allows a non-root owner to set roles to `None`), which is a partial mitigation not present in the LSP6 report — but nothing in the protocol forces or even warns about this, and the residual-permission window exists by default on every transfer.

### Likelihood Explanation
Likelihood is Medium-Low: this requires (a) a collection creator/former owner to have deliberately retained a team role prior to transferring ownership, and (b) a new owner who does not proactively call `set_team` (or query `CollectionRoleOf`) after accepting ownership. This is analogous to the "conditionals and unfounded trust required from the receiver" reasoning the judge used to cap the original finding at Medium rather than High. It is a genuine, reachable design gap in mainline `pallet-nfts`, not a mock/test-only artifact, and it is deployed as-is in Asset Hub runtimes that use this pallet.

### Recommendation
- Clarify in `transfer_ownership`/`force_collection_owner` documentation that team roles (`CollectionRoleOf`) are *not* reset by ownership transfer, and/or
- Provide an option (or make it the default) for `do_transfer_ownership` to call `Self::clear_roles(&collection)` so that team roles are reset on transfer, requiring the new owner to explicitly re-appoint any Issuer/Admin/Freezer, mirroring the salt/nonce-based invalidation approach the LUKSO team proposed in the source report.
- At minimum, emit a warning event or require explicit acknowledgment (similar to `set_accept_ownership`) when a collection with active non-owner team roles is transferred.

### Proof of Concept
Status: **not executed** — this is a reproduction sketch built from verified, existing pallet APIs and the pallet's own test harness (`substrate/frame/nfts/src/tests.rs`), not a run test. It was not executed in this session and no result is claimed.

```rust
// Sketch using existing pallet-nfts unit-test scaffolding (new_test_ext, account(), etc.)
new_test_ext().execute_with(|| {
    // 1. Attacker creates a collection and appoints themselves Admin/Freezer/Issuer.
    assert_ok!(Nfts::create(RuntimeOrigin::signed(account(1)), account(1),
        collection_config_with_all_settings_enabled()));
    assert_ok!(Nfts::set_team(
        RuntimeOrigin::signed(account(1)),
        0,
        Some(account(1)), // Issuer
        Some(account(1)), // Admin
        Some(account(1)), // Freezer
    ));

    // 2. Attacker transfers collection ownership to victim (account 2), who accepts.
    assert_ok!(Nfts::set_accept_ownership(RuntimeOrigin::signed(account(2)), Some(0)));
    assert_ok!(Nfts::transfer_ownership(RuntimeOrigin::signed(account(1)), 0, account(2)));

    // 3. Victim (account 2) is now the "owner" per `Collection::owner`, but:
    assert_eq!(
        CollectionRoleOf::<Test>::get(0, account(1)),
        Some(CollectionRoles(CollectionRole::Issuer | CollectionRole::Admin | CollectionRole::Freezer))
    ); // attacker still holds full team roles

    // 4. Attacker (still Freezer/Admin) can lock item transfer / lock item properties
    //    on items minted by the new owner, without the new owner's consent, e.g.:
    // assert_ok!(Nfts::lock_item_transfer(RuntimeOrigin::signed(account(1)), 0, item_id));
});
```

Failed guard: `do_transfer_ownership` (and `force_collection_owner`) contain no `ensure!`/mutation touching `CollectionRoleOf`, so step 3's assertion that the attacker's roles persist is expected to hold given the code at `substrate/frame/nfts/src/features/transfer.rs:124-162`. Deployment evidence: `pallet-nfts` (with this exact `transfer_ownership`/`do_set_team` logic) is compiled into the Asset Hub Westend/Rococo runtimes (weight files under `cumulus/parachains/runtimes/assets/asset-hub-*/src/weights/pallet_nfts.rs`), confirming it is live production code, not test/mock-only.

### Citations

**File:** substrate/frame/nfts/src/features/transfer.rs (L124-162)
```rust
	pub(crate) fn do_transfer_ownership(
		origin: T::AccountId,
		collection: T::CollectionId,
		new_owner: T::AccountId,
	) -> DispatchResult {
		// Check if the new owner is acceptable based on the collection's acceptance settings.
		let acceptable_collection = OwnershipAcceptance::<T, I>::get(&new_owner);
		ensure!(acceptable_collection.as_ref() == Some(&collection), Error::<T, I>::Unaccepted);

		// Try to retrieve and mutate the collection details.
		Collection::<T, I>::try_mutate(collection, |maybe_details| {
			let details = maybe_details.as_mut().ok_or(Error::<T, I>::UnknownCollection)?;
			// Check if the `origin` is the current owner of the collection.
			ensure!(origin == details.owner, Error::<T, I>::NoPermission);
			if details.owner == new_owner {
				return Ok(());
			}

			// Move the deposit to the new owner.
			T::Currency::repatriate_reserved(
				&details.owner,
				&new_owner,
				details.owner_deposit,
				Reserved,
			)?;

			// Update account ownership information.
			CollectionAccount::<T, I>::remove(&details.owner, &collection);
			CollectionAccount::<T, I>::insert(&new_owner, &collection, ());

			details.owner = new_owner.clone();
			OwnershipAcceptance::<T, I>::remove(&new_owner);
			frame_system::Pallet::<T>::dec_consumers(&new_owner);

			// Emit `OwnerChanged` event.
			Self::deposit_event(Event::OwnerChanged { collection, new_owner });
			Ok(())
		})
	}
```

**File:** substrate/frame/nfts/src/features/transfer.rs (L205-233)
```rust
	pub(crate) fn do_force_collection_owner(
		collection: T::CollectionId,
		owner: T::AccountId,
	) -> DispatchResult {
		// Try to retrieve and mutate the collection details.
		Collection::<T, I>::try_mutate(collection, |maybe_details| {
			let details = maybe_details.as_mut().ok_or(Error::<T, I>::UnknownCollection)?;
			if details.owner == owner {
				return Ok(());
			}

			// Move the deposit to the new owner.
			T::Currency::repatriate_reserved(
				&details.owner,
				&owner,
				details.owner_deposit,
				Reserved,
			)?;

			// Update collection accounts and set the new owner.
			CollectionAccount::<T, I>::remove(&details.owner, &collection);
			CollectionAccount::<T, I>::insert(&owner, &collection, ());
			details.owner = owner.clone();

			// Emit `OwnerChanged` event.
			Self::deposit_event(Event::OwnerChanged { collection, new_owner: owner });
			Ok(())
		})
	}
```

**File:** substrate/frame/nfts/src/features/roles.rs (L38-105)
```rust
	pub(crate) fn do_set_team(
		maybe_check_owner: Option<T::AccountId>,
		collection: T::CollectionId,
		issuer: Option<T::AccountId>,
		admin: Option<T::AccountId>,
		freezer: Option<T::AccountId>,
	) -> DispatchResult {
		Collection::<T, I>::try_mutate(collection, |maybe_details| {
			let details = maybe_details.as_mut().ok_or(Error::<T, I>::UnknownCollection)?;
			let is_root = maybe_check_owner.is_none();
			if let Some(check_origin) = maybe_check_owner {
				ensure!(check_origin == details.owner, Error::<T, I>::NoPermission);
			}

			let roles_map = [
				(issuer.clone(), CollectionRole::Issuer),
				(admin.clone(), CollectionRole::Admin),
				(freezer.clone(), CollectionRole::Freezer),
			];

			// only root can change the role from `None` to `Some(account)`
			if !is_root {
				for (account, role) in roles_map.iter() {
					if account.is_some() {
						ensure!(
							Self::find_account_by_role(&collection, *role).is_some(),
							Error::<T, I>::NoPermission
						);
					}
				}
			}

			let roles = roles_map
				.into_iter()
				.filter_map(|(account, role)| account.map(|account| (account, role)))
				.collect();

			let account_to_role = Self::group_roles_by_account(roles);

			// Delete the previous records.
			Self::clear_roles(&collection)?;

			// Insert new records.
			for (account, roles) in account_to_role {
				CollectionRoleOf::<T, I>::insert(&collection, &account, roles);
			}

			Self::deposit_event(Event::TeamChanged { collection, issuer, admin, freezer });
			Ok(())
		})
	}

	/// Clears all the roles in a specified collection.
	///
	/// - `collection_id`: A collection to clear the roles in.
	///
	/// This function clears all the roles associated with the given `collection_id`. It throws an
	/// error if some of the roles were left in storage, indicating that the maximum number of roles
	/// may need to be adjusted.
	pub(crate) fn clear_roles(collection_id: &T::CollectionId) -> Result<(), DispatchError> {
		let res = CollectionRoleOf::<T, I>::clear_prefix(
			&collection_id,
			CollectionRoles::max_roles() as u32,
			None,
		);
		ensure!(res.maybe_cursor.is_none(), Error::<T, I>::RolesNotCleared);
		Ok(())
	}
```

**File:** substrate/frame/nfts/src/lib.rs (L1176-1197)
```rust
		/// Change the Owner of a collection.
		///
		/// Origin must be Signed and the sender should be the Owner of the `collection`.
		///
		/// - `collection`: The collection whose owner should be changed.
		/// - `owner`: The new Owner of this collection. They must have called
		///   `set_accept_ownership` with `collection` in order for this operation to succeed.
		///
		/// Emits `OwnerChanged`.
		///
		/// Weight: `O(1)`
		#[pallet::call_index(11)]
		#[pallet::weight(T::WeightInfo::transfer_ownership())]
		pub fn transfer_ownership(
			origin: OriginFor<T>,
			collection: T::CollectionId,
			new_owner: AccountIdLookupOf<T>,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;
			let new_owner = T::Lookup::lookup(new_owner)?;
			Self::do_transfer_ownership(origin, collection, new_owner)
		}
```

**File:** substrate/frame/nfts/src/lib.rs (L1199-1231)
```rust
		/// Change the Issuer, Admin and Freezer of a collection.
		///
		/// Origin must be either `ForceOrigin` or Signed and the sender should be the Owner of the
		/// `collection`.
		///
		/// Note: by setting the role to `None` only the `ForceOrigin` will be able to change it
		/// after to `Some(account)`.
		///
		/// - `collection`: The collection whose team should be changed.
		/// - `issuer`: The new Issuer of this collection.
		/// - `admin`: The new Admin of this collection.
		/// - `freezer`: The new Freezer of this collection.
		///
		/// Emits `TeamChanged`.
		///
		/// Weight: `O(1)`
		#[pallet::call_index(12)]
		#[pallet::weight(T::WeightInfo::set_team())]
		pub fn set_team(
			origin: OriginFor<T>,
			collection: T::CollectionId,
			issuer: Option<AccountIdLookupOf<T>>,
			admin: Option<AccountIdLookupOf<T>>,
			freezer: Option<AccountIdLookupOf<T>>,
		) -> DispatchResult {
			let maybe_check_owner = T::ForceOrigin::try_origin(origin)
				.map(|_| None)
				.or_else(|origin| ensure_signed(origin).map(Some).map_err(DispatchError::from))?;
			let issuer = issuer.map(T::Lookup::lookup).transpose()?;
			let admin = admin.map(T::Lookup::lookup).transpose()?;
			let freezer = freezer.map(T::Lookup::lookup).transpose()?;
			Self::do_set_team(maybe_check_owner, collection, issuer, admin, freezer)
		}
```

**File:** substrate/frame/nfts/src/features/lock.rs (L68-116)
```rust
	pub(crate) fn do_lock_item_transfer(
		origin: T::AccountId,
		collection: T::CollectionId,
		item: T::ItemId,
	) -> DispatchResult {
		ensure!(
			Self::has_role(&collection, &origin, CollectionRole::Freezer),
			Error::<T, I>::NoPermission
		);

		let mut config = Self::get_item_config(&collection, &item)?;
		if !config.has_disabled_setting(ItemSetting::Transferable) {
			config.disable_setting(ItemSetting::Transferable);
		}
		ItemConfigOf::<T, I>::insert(&collection, &item, config);

		Self::deposit_event(Event::<T, I>::ItemTransferLocked { collection, item });
		Ok(())
	}

	/// Unlocks the transfer of an item within a collection.
	///
	/// The origin must have the `Freezer` role within the collection to unlock the transfer of the
	/// item. This function enables the `Transferable` setting on the item, allowing it to be
	/// transferred to other accounts.
	///
	/// - `origin`: The origin of the transaction, representing the account attempting to unlock the
	///   item transfer.
	/// - `collection`: The identifier of the collection to which the item belongs.
	/// - `item`: The identifier of the item to be unlocked for transfer.
	pub(crate) fn do_unlock_item_transfer(
		origin: T::AccountId,
		collection: T::CollectionId,
		item: T::ItemId,
	) -> DispatchResult {
		ensure!(
			Self::has_role(&collection, &origin, CollectionRole::Freezer),
			Error::<T, I>::NoPermission
		);

		let mut config = Self::get_item_config(&collection, &item)?;
		if config.has_disabled_setting(ItemSetting::Transferable) {
			config.enable_setting(ItemSetting::Transferable);
		}
		ItemConfigOf::<T, I>::insert(&collection, &item, config);

		Self::deposit_event(Event::<T, I>::ItemTransferUnlocked { collection, item });
		Ok(())
	}
```

**File:** substrate/frame/nfts/src/features/lock.rs (L133-165)
```rust
	pub(crate) fn do_lock_item_properties(
		maybe_check_origin: Option<T::AccountId>,
		collection: T::CollectionId,
		item: T::ItemId,
		lock_metadata: bool,
		lock_attributes: bool,
	) -> DispatchResult {
		if let Some(check_origin) = &maybe_check_origin {
			ensure!(
				Self::has_role(&collection, &check_origin, CollectionRole::Admin),
				Error::<T, I>::NoPermission
			);
		}

		ItemConfigOf::<T, I>::try_mutate(collection, item, |maybe_config| {
			let config = maybe_config.as_mut().ok_or(Error::<T, I>::UnknownItem)?;

			if lock_metadata {
				config.disable_setting(ItemSetting::UnlockedMetadata);
			}
			if lock_attributes {
				config.disable_setting(ItemSetting::UnlockedAttributes);
			}

			Self::deposit_event(Event::<T, I>::ItemPropertiesLocked {
				collection,
				item,
				lock_metadata,
				lock_attributes,
			});
			Ok(())
		})
	}
```

**File:** substrate/frame/nfts/src/types.rs (L558-569)
```rust
/// Support for up to 8 different roles for collections.
#[bitflags]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub enum CollectionRole {
	/// Can mint items.
	Issuer,
	/// Can freeze items.
	Freezer,
	/// Can thaw items, force transfers and burn items from any account.
	Admin,
}
```

**File:** substrate/frame/nfts/src/features/create_delete_item.rs (L151-154)
```rust
		ensure!(
			Self::has_role(&collection, &signer, CollectionRole::Issuer),
			Error::<T, I>::NoPermission
		);
```
