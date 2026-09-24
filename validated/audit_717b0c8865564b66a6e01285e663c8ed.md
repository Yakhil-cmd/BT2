[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** substrate/frame/nfts/src/features/roles.rs (L38-88)
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
```

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
