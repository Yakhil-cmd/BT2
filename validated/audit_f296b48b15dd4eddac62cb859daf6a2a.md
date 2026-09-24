No vulnerability found for this question.

The report describes an application-specific bug in the Solidity contract `FantiumNFTV3.sol` — a token ID scheme where collections are partitioned into fixed-size blocks (1,000,000 ids per collection, 10,000 ids per "version"), such that incrementing a token's version 100 times causes its ID to overflow into the next collection's ID space. This is a bespoke encoding bug tied to that contract's custom `tokenVersionUpgrade` arithmetic, not a general blockchain/FRAME concept.

I searched the Polkadot SDK's NFT-related pallets (`pallet-nfts`, `pallet-uniques`) and the `pallet-derivatives` module for anything resembling this partitioned/versioned ID scheme:

- `pallet-nfts`'s minting logic uses a flat `T::ItemId` per `T::CollectionId` with no version-based ID partitioning or overflow-into-next-collection behavior. Item existence and max-supply checks are enforced independently per collection via `Collection::<T,I>::try_mutate` and `CollectionConfig::max_supply` [1](#0-0) .
- `pallet-uniques` has the analogous `do_mint` with a `CollectionMaxSupply` check that simply rejects minting when full, with no ID-space encoding that could jump between collections [2](#0-1) .
- Collection IDs and item IDs are independent, generic types (`T::CollectionId`, `T::ItemId`) with `NextCollectionId` incremented separately from item IDs, so there's no shared numeric ID space where an item ID could arithmetically roll over into a different collection's namespace [3](#0-2) .
- `pallet-derivatives` also keeps collection ID and per-collection incremental token ID as separate concerns (`ConcatIncrementalExtra`), not a single packed numeric space subject to overflow [4](#0-3) .

There is no reachable entry point (extrinsic, XCM instruction, or contract call) in the Polkadot SDK that encodes a "version" into a token ID with a fixed per-collection ID budget, so there is no structural analog to the reported "jump between collections" bug. This finding is specific to the external Solidity contract's custom ID-packing logic and does not map onto any FRAME pallet, XCM component, or Polkadot SDK primitive.

### Citations

**File:** substrate/frame/nfts/src/features/create_delete_item.rs (L44-68)
```rust
	pub fn do_mint(
		collection: T::CollectionId,
		item: T::ItemId,
		maybe_depositor: Option<T::AccountId>,
		mint_to: T::AccountId,
		item_config: ItemConfig,
		with_details_and_config: impl FnOnce(
			&CollectionDetailsFor<T, I>,
			&CollectionConfigFor<T, I>,
		) -> DispatchResult,
	) -> DispatchResult {
		ensure!(!Item::<T, I>::contains_key(collection, item), Error::<T, I>::AlreadyExists);

		Collection::<T, I>::try_mutate(
			&collection,
			|maybe_collection_details| -> DispatchResult {
				let collection_details =
					maybe_collection_details.as_mut().ok_or(Error::<T, I>::UnknownCollection)?;

				let collection_config = Self::get_collection_config(&collection)?;
				with_details_and_config(collection_details, &collection_config)?;

				if let Some(max_supply) = collection_config.max_supply {
					ensure!(collection_details.items < max_supply, Error::<T, I>::MaxSupplyReached);
				}
```

**File:** substrate/frame/uniques/src/functions.rs (L186-204)
```rust
		ensure!(
			!Item::<T, I>::contains_key(collection.clone(), item),
			Error::<T, I>::AlreadyExists
		);

		Collection::<T, I>::try_mutate(
			&collection,
			|maybe_collection_details| -> DispatchResult {
				let collection_details =
					maybe_collection_details.as_mut().ok_or(Error::<T, I>::UnknownCollection)?;

				with_details(collection_details)?;

				if let Ok(max_supply) = CollectionMaxSupply::<T, I>::try_get(&collection) {
					ensure!(collection_details.items < max_supply, Error::<T, I>::MaxSupplyReached);
				}

				let items =
					collection_details.items.checked_add(1).ok_or(ArithmeticError::Overflow)?;
```

**File:** substrate/frame/nfts/src/common_functions.rs (L64-68)
```rust
	pub(crate) fn set_next_collection_id(collection: T::CollectionId) {
		let next_id = collection.increment();
		NextCollectionId::<T, I>::set(next_id);
		Self::deposit_event(Event::NextCollectionIdIncremented { next_id });
	}
```

**File:** substrate/frame/derivatives/src/mock/mod.rs (L382-393)
```rust
/// * Takes `CollectionAutoId` (the NFT derivative collection ID)
/// * Gets the associated extra data (current in-collection token ID) using the
///   `AutoIdDerivativeCollections`,
/// * Makes the `FullNftId` using the collection ID and current token ID,
/// * Creates a derivative NFT using the `FullNftId`
/// * Increments the token ID and sets it as the derivative collection's extra data.
pub type DeriveNft = ConcatIncrementalExtra<
	CollectionAutoId,
	NftLocalId,
	AutoIdDerivativeCollections,
	PredefinedIdNfts,
>;
```
