No vulnerability found for this question.

The reported issue is an ORM/web-service class of bug: `TypeORM`'s `repository.save()` performing an implicit UPSERT because a client-supplied `id` field is accepted directly into a create DTO without an allowlist, enabling cross-tenant object takeover in a Node.js REST API. This is inherently tied to an object-relational mapper's save-semantics and HTTP request-body-to-entity binding — a pattern that does not exist in FRAME's runtime dispatch model.

Across the FRAME code inspected, pallet `create` extrinsics take an explicit, typed `id` parameter but never blindly call an ORM-style `save()`. Instead they explicitly check for existence before insertion, e.g. `pallet-assets`'s `create`/`force_create` both perform `ensure!(!Asset::<T, I>::contains_key(&id), Error::<T, I>::InUse)` before calling `Asset::<T, I>::insert(...)` [1](#0-0) [2](#0-1) . Similarly, `pallet-uniques`'s asset-ops `Item::create` uses `do_mint`, which is guarded by ownership/permission checks in the `CheckOrigin` wrapper (`ensure!(collection_details.issuer == signer, Error::<T, I>::NoPermission)`), and `try_mutate` based unique-item collections explicitly reject creation on an already-occupied id via `Error::AlreadyExists` [3](#0-2) [4](#0-3) .

Because FRAME storage primitives (`StorageMap::insert`, `try_mutate`) require explicit `contains_key`/`ensure!` checks written by each pallet author rather than an implicit "save-with-PK-means-upsert" behavior baked into the framework, there is no direct architectural analog to a mass-assignment/implicit-UPSERT vulnerability where a client-controlled primary key transparently causes an unauthenticated update path. Every "create" call path I found in scope enforces an existence check (and, where relevant, an ownership/origin check) prior to any storage write, which is precisely the missing control described in the Flowise report. Forcing this bug class onto FRAME's extrinsic/storage-map model would not be a demonstrable vulnerability but an invented one.

### Citations

**File:** substrate/frame/assets/src/lib.rs (L843-863)
```rust
		pub fn create(
			origin: OriginFor<T>,
			id: T::AssetIdParameter,
			admin: AccountIdLookupOf<T>,
			min_balance: T::Balance,
		) -> DispatchResult {
			let id: T::AssetId = id.into();
			let owner = T::CreateOrigin::ensure_origin(origin, &id)?;
			let admin = T::Lookup::lookup(admin)?;

			ensure!(!Asset::<T, I>::contains_key(&id), Error::<T, I>::InUse);
			ensure!(!min_balance.is_zero(), Error::<T, I>::MinBalanceZero);

			if let Some(next_id) = T::AssetIdAllocator::next() {
				ensure!(id == next_id, Error::<T, I>::BadAssetId);
			}

			let deposit = T::AssetDeposit::get();
			T::Currency::reserve(&owner, deposit)?;

			Asset::<T, I>::insert(
```

**File:** substrate/frame/assets/src/functions.rs (L760-775)
```rust
	pub(super) fn do_force_create(
		id: T::AssetId,
		owner: T::AccountId,
		is_sufficient: bool,
		min_balance: T::Balance,
		enforce_allocator: bool,
	) -> DispatchResult {
		ensure!(!Asset::<T, I>::contains_key(&id), Error::<T, I>::InUse);
		ensure!(!min_balance.is_zero(), Error::<T, I>::MinBalanceZero);
		if enforce_allocator {
			if let Some(next_id) = T::AssetIdAllocator::next() {
				ensure!(id == next_id, Error::<T, I>::BadAssetId);
			}
		}

		Asset::<T, I>::insert(
```

**File:** substrate/frame/uniques/src/asset_ops/item.rs (L91-124)
```rust
impl<T: Config<I>, I: 'static> Create<WithItemConfig<T, I>> for Item<Pallet<T, I>> {
	fn create(
		strategy: WithItemConfig<T, I>,
	) -> Result<(T::CollectionId, T::ItemId), DispatchError> {
		let WithConfig { config: ConfigValue::<_>(owner), extra: id_assignment } = strategy;
		let (collection, item) = id_assignment.params;

		<Pallet<T, I>>::do_mint(collection.clone(), item, owner, |_| Ok(()))?;

		Ok((collection, item))
	}
}

impl<T: Config<I>, I: 'static> Create<CheckOrigin<T::RuntimeOrigin, WithItemConfig<T, I>>>
	for Item<Pallet<T, I>>
{
	fn create(
		strategy: CheckOrigin<T::RuntimeOrigin, WithItemConfig<T, I>>,
	) -> Result<(T::CollectionId, T::ItemId), DispatchError> {
		let CheckOrigin(
			origin,
			WithConfig { config: ConfigValue::<_>(owner), extra: id_assignment },
		) = strategy;
		let (collection, item) = id_assignment.params;

		let signer = ensure_signed(origin)?;

		<Pallet<T, I>>::do_mint(collection.clone(), item, owner, |collection_details| {
			ensure!(collection_details.issuer == signer, Error::<T, I>::NoPermission);
			Ok(())
		})?;

		Ok((collection, item))
	}
```

**File:** substrate/frame/derivatives/src/mock/predefined_id_collections.rs (L32-51)
```rust
	fn create(
		strategy: WithConfig<ConfigValue<Owner<AccountId>>, PredefinedId<AssetId>>,
	) -> Result<AssetId, DispatchError> {
		let WithConfig { config: ConfigValue(owner), extra: id_assignment } = strategy;
		let id = id_assignment.params;

		unique_items::ItemOwner::<Test, PredefinedIdCollectionsInstance>::try_mutate(
			id.clone(),
			|current_owner| {
				if current_owner.is_none() {
					*current_owner = Some(owner);
					Ok(())
				} else {
					Err(unique_items::Error::<Test, PredefinedIdCollectionsInstance>::AlreadyExists)
				}
			},
		)?;

		Ok(id)
	}
```
