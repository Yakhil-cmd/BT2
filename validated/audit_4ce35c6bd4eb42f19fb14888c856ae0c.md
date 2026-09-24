[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** substrate/frame/core-fellowship/src/lib.rs (L731-741)
```rust
		/// Convert a rank into a `0..RANK_COUNT` index suitable for the arrays in Params.
		///
		/// Rank 1 becomes index 0, rank `RANK_COUNT` becomes index `RANK_COUNT - 1`. Any rank not
		/// in the range `1..=RANK_COUNT` is `None`.
		pub(crate) fn rank_to_index(rank: RankOf<T, I>) -> Option<usize> {
			if rank == 0 || rank > T::MaxRank::get() {
				None
			} else {
				Some((rank - 1) as usize)
			}
		}
```

**File:** substrate/frame/core-fellowship/src/lib.rs (L751-768)
```rust
	impl<T: Config<I>, I: 'static> GetSalary<RankOf<T, I>, T::AccountId, T::Balance> for Pallet<T, I> {
		fn get_salary(rank: RankOf<T, I>, who: &T::AccountId) -> T::Balance {
			let index = match Self::rank_to_index(rank) {
				Some(i) => i,
				None => return Zero::zero(),
			};
			let member = match Member::<T, I>::get(who) {
				Some(m) => m,
				None => return Zero::zero(),
			};
			let params = Params::<T, I>::get();
			let salary =
				if member.is_active { params.active_salary } else { params.passive_salary };
			// `GetSalary::get_salary` returns `T::Balance` directly, not a `Result`, so an
			// out-of-range rank can't be rejected here the way `bump`/`promote` reject it; fall
			// back to zero, consistent with the early returns above.
			salary.get(index).copied().unwrap_or_default()
		}
```

**File:** prdoc/pr_13182.prdoc (L1-12)
```text
title: 'core-fellowship: avoid panic on undersized Params salary/period vectors'
doc:
- audience: Runtime Dev
  description: |-
    `Pallet::get_salary` computed an index from the member's rank and then indexed the `active_salary `or `passive_salary` vector directly. The bump and promote calls did the same thing to `demotion_period `and `min_promotion_period`. All four of these vectors are BoundedVec fields bounded only by MaxRank, so a privileged set_params call is free to store a shorter vector, including the empty default. Once that happens, any of these three call sites panics for a member whose rank sits past the end of the stored vector, which traps the extrinsic instead of failing gracefully.

    This changes all three sites to look up the index with get and fall back to the type's default when the entry is missing, so a rank past the end of the vector now degrades to zero salary, a zero demotion period or a zero minimum promotion period, the same way the pallet already treats rank 0 and untracked members. No panic path remains.

    Closes #13141
crates:
- name: pallet-core-fellowship
  bump: patch
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L1755-1794)
```rust
			let entry = if let Some(entry) = AuthorizedAliases::<T>::get(&versioned_origin) {
				// entry already exists, update it
				let (mut aliasers, mut ticket) = (entry.aliasers, entry.ticket);
				if let Some(aliaser) =
					aliasers.iter_mut().find(|aliaser| aliaser.location == versioned_aliaser)
				{
					// if the aliaser already exists, just update its expiry block
					aliaser.expiry = expires;
				} else {
					// if it doesn't, we try to add it
					let aliaser =
						OriginAliaser { location: versioned_aliaser.clone(), expiry: expires };
					aliasers.try_push(aliaser).map_err(|_| {
						tracing::debug!(
							target: "xcm::pallet_xcm::add_authorized_alias",
							"Failed to add new aliaser to existing entry",
						);
						Error::<T>::TooManyAuthorizedAliases
					})?;
					// we try to update the ticket (the storage deposit)
					ticket = ticket.update(&signed_origin, aliasers_footprint(aliasers.len()))?;
				}
				AuthorizedAliasesEntry { aliasers, ticket }
			} else {
				// add new entry with its first alias
				let ticket = TicketOf::<T>::new(&signed_origin, aliasers_footprint(1))?;
				let aliaser =
					OriginAliaser { location: versioned_aliaser.clone(), expiry: expires };
				let mut aliasers = BoundedVec::<OriginAliaser, MaxAuthorizedAliases>::new();
				aliasers.try_push(aliaser).map_err(|error| {
					tracing::debug!(
						target: "xcm::pallet_xcm::add_authorized_alias", ?error,
						"Failed to add first aliaser to new entry",
					);
					Error::<T>::TooManyAuthorizedAliases
				})?;
				AuthorizedAliasesEntry { aliasers, ticket }
			};
			// write to storage
			AuthorizedAliases::<T>::insert(&versioned_origin, entry);
```

**File:** polkadot/xcm/src/v3/junctions.rs (L539-580)
```rust
	/// Returns a mutable reference to the junction at index `i`, or `None` if the location doesn't
	/// contain that many elements.
	pub fn at_mut(&mut self, i: usize) -> Option<&mut Junction> {
		Some(match (i, self) {
			(0, Junctions::X1(ref mut a)) => a,
			(0, Junctions::X2(ref mut a, ..)) => a,
			(0, Junctions::X3(ref mut a, ..)) => a,
			(0, Junctions::X4(ref mut a, ..)) => a,
			(0, Junctions::X5(ref mut a, ..)) => a,
			(0, Junctions::X6(ref mut a, ..)) => a,
			(0, Junctions::X7(ref mut a, ..)) => a,
			(0, Junctions::X8(ref mut a, ..)) => a,
			(1, Junctions::X2(_, ref mut a)) => a,
			(1, Junctions::X3(_, ref mut a, ..)) => a,
			(1, Junctions::X4(_, ref mut a, ..)) => a,
			(1, Junctions::X5(_, ref mut a, ..)) => a,
			(1, Junctions::X6(_, ref mut a, ..)) => a,
			(1, Junctions::X7(_, ref mut a, ..)) => a,
			(1, Junctions::X8(_, ref mut a, ..)) => a,
			(2, Junctions::X3(_, _, ref mut a)) => a,
			(2, Junctions::X4(_, _, ref mut a, ..)) => a,
			(2, Junctions::X5(_, _, ref mut a, ..)) => a,
			(2, Junctions::X6(_, _, ref mut a, ..)) => a,
			(2, Junctions::X7(_, _, ref mut a, ..)) => a,
			(2, Junctions::X8(_, _, ref mut a, ..)) => a,
			(3, Junctions::X4(_, _, _, ref mut a)) => a,
			(3, Junctions::X5(_, _, _, ref mut a, ..)) => a,
			(3, Junctions::X6(_, _, _, ref mut a, ..)) => a,
			(3, Junctions::X7(_, _, _, ref mut a, ..)) => a,
			(3, Junctions::X8(_, _, _, ref mut a, ..)) => a,
			(4, Junctions::X5(_, _, _, _, ref mut a)) => a,
			(4, Junctions::X6(_, _, _, _, ref mut a, ..)) => a,
			(4, Junctions::X7(_, _, _, _, ref mut a, ..)) => a,
			(4, Junctions::X8(_, _, _, _, ref mut a, ..)) => a,
			(5, Junctions::X6(_, _, _, _, _, ref mut a)) => a,
			(5, Junctions::X7(_, _, _, _, _, ref mut a, ..)) => a,
			(5, Junctions::X8(_, _, _, _, _, ref mut a, ..)) => a,
			(6, Junctions::X7(_, _, _, _, _, _, ref mut a)) => a,
			(6, Junctions::X8(_, _, _, _, _, _, ref mut a, ..)) => a,
			(7, Junctions::X8(_, _, _, _, _, _, _, ref mut a)) => a,
			_ => return None,
		})
```
