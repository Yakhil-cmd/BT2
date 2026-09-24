No vulnerability found for this question.

The reported issue is specific to Palmera's Solidity-based hierarchical safe/organization contract, where `removeWholeTree` iterates over child safes calling `disableSafeLeadRoles` but omits that call for the root safe before `_exitSafe(rootSafe)` is invoked. This is a contract-specific state-cleanup bug in a bespoke role/permission mapping (`safes[org][safe]`, `disableSafeLeadRoles`) that has no structural equivalent in the Polkadot SDK codebase I was able to locate.

I searched for FRAME analogs involving hierarchical role clearing during removal (nomination-pools role updates, NFTs collection team roles/`clear_roles`, ranked-collective member removal, fork-tree pruning/`drain_filter`), and none of them exhibit the same pattern of a recursive/tree removal routine that clears child-node privileges but skips the final root node before its own removal — each of these FRAME implementations either clears state uniformly for all nodes or doesn't carry over "lead role" style residual privileges to a root entity that could subsequently be reused elsewhere. [1](#0-0) [2](#0-1) [3](#0-2) 

Per the instructions, forcing this EVM-specific "Safe org tree" role-cleanup bug onto FRAME's pallet architecture would not represent a real, demonstrable vulnerability, so no analog is reported.

### Citations

**File:** substrate/frame/nfts/src/features/roles.rs (L90-105)
```rust
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

**File:** substrate/frame/nomination-pools/src/lib.rs (L2780-2805)
```rust
		/// Update the roles of the pool.
		///
		/// The root is the only entity that can change any of the roles, including itself,
		/// excluding the depositor, who can never change.
		///
		/// It emits an event, notifying UIs of the role change. This event is quite relevant to
		/// most pool members and they should be informed of changes to pool roles.
		#[pallet::call_index(12)]
		#[pallet::weight(T::WeightInfo::update_roles())]
		pub fn update_roles(
			origin: OriginFor<T>,
			pool_id: PoolId,
			new_root: ConfigOp<T::AccountId>,
			new_nominator: ConfigOp<T::AccountId>,
			new_bouncer: ConfigOp<T::AccountId>,
		) -> DispatchResult {
			let mut bonded_pool = match ensure_root(origin.clone()) {
				Ok(()) => BondedPool::<T>::get(pool_id).ok_or(Error::<T>::PoolNotFound)?,
				Err(sp_runtime::traits::BadOrigin) => {
					let who = ensure_signed(origin)?;
					let bonded_pool =
						BondedPool::<T>::get(pool_id).ok_or(Error::<T>::PoolNotFound)?;
					ensure!(bonded_pool.can_update_roles(&who), Error::<T>::DoesNotHavePermission);
					bonded_pool
				},
			};
```

**File:** substrate/utils/fork-tree/src/lib.rs (L714-722)
```rust
	/// Remove from the tree some nodes (and their subtrees) using a `filter` predicate.
	///
	/// The `filter` is called over tree nodes and returns a filter action:
	/// - `Remove` if the node and its subtree should be removed;
	/// - `KeepNode` if we should maintain the node and keep processing the tree.
	/// - `KeepTree` if we should maintain the node and its entire subtree.
	///
	/// An iterator over all the pruned nodes is returned.
	pub fn drain_filter<F>(&mut self, filter: F) -> impl Iterator<Item = (H, N, V)>
```
