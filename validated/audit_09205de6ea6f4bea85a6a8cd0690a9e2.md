### Title
Missing ownership verification in `NonFungiblesTransferAdapter`/`NonFungibleTransferAdapter::transfer_asset` allows theft of any NFT via XCM `TransferAsset` - ([File: polkadot/xcm/xcm-builder/src/nonfungibles_adapter.rs])

### Summary
The XCM `TransactAsset` adapters used to move `pallet-uniques`/`pallet-nfts` items (`NonFungiblesTransferAdapter::transfer_asset` and `NonFungibleTransferAdapter::transfer_asset`) never verify that the `from` location supplied to `transfer_asset` is the current owner of the NFT being moved. They only resolve the destination and then unconditionally call the underlying `nonfungibles::Transfer::transfer` / `nonfungible::Transfer::transfer` implementation, which for both `pallet-uniques` and `pallet-nfts` is wired with an empty ownership-check closure (`|_, _| Ok(())`). This mirrors exactly the reported bug class ("`transferFrom` lacks an owner == from check"): any account able to execute a `TransferAsset` XCM instruction can name an arbitrary NFT it does not own and move it to any beneficiary.

### Finding Description
`NonFungiblesTransferAdapter::transfer_asset` (used inside `NonFungiblesAdapter`, the "works for everything" transactor) is defined as: [1](#0-0) 

Note that the `from: &Location` parameter is only used for tracing — it is never converted to an `AccountId` nor compared against the item's current owner before `Assets::transfer(&class, &instance, &destination)` is invoked. The single-collection variant has the identical flaw: [2](#0-1) 

Both `NonFungibleAdapter`/`NonFungiblesAdapter` ("works for everything") delegate their `transfer_asset` to these unchecked implementations: [3](#0-2) [4](#0-3) 

Contrast this with the `Mutate` (teleport) side of the same file, which *does* check ownership before allowing a reduction: [5](#0-4) 

Crucially, the downstream pallet implementations of `nonfungibles::Transfer`/`nonfungible::Transfer` also perform **no** ownership check — they call `do_transfer` with a no-op closure: [6](#0-5) [7](#0-6) 

`do_transfer` itself performs no ownership verification either — it only checks lock/transferability flags and then unconditionally moves the item to `dest`: [8](#0-7) 

This is in sharp contrast to the properly-guarded dispatchable entry points of the same pallets, which explicitly require `details.owner == origin` or a valid approval before calling `do_transfer`: [9](#0-8) [10](#0-9) 

In other words, the ownership check that every dispatchable-level `transfer` extrinsic performs is bypassed entirely when the transfer path is driven through the XCM `TransferAsset` instruction against these transactors, because the `Transfer` trait contract used by the adapter provides no way to convey/enforce "check_owner", unlike `Mutate::burn(item, maybe_check_owner)`.

These adapters are wired into production Asset Hub configuration: [11](#0-10) 
(confirmed via search matches for `NonFungiblesAdapter`/related identifiers in `asset-hub-rococo/src/xcm_config.rs` and `asset-hub-westend/src/xcm_config.rs`, plus `coretime-westend/src/xcm_config.rs`).

### Impact Explanation
If reachable by an ordinary signed account (e.g., via `pallet_xcm::execute` local execution or a remote XCM program that a user can craft, as long as the runtime's barrier permits a `TransferAsset` instruction for that origin), this allows unconditional theft of any `pallet-uniques`/`pallet-nfts` item registered for XCM by simply naming the victim's `(collection, item)` as the asset and any account as beneficiary — no ownership, no approval, and no signature from the victim is required. This is a direct, deterministic asset-theft primitive (Critical/High class per the audit report's own classification of "unauthorized transfer of assets").

### Likelihood Explanation
Reachability depends entirely on runtime-specific `Barrier` configuration for local XCM execution (`pallet_xcm::execute`) or on whether inbound XCM programs from other chains/locations can reach a `TransferAsset` instruction against the NFT `AssetTransactor`. I was not able to fully verify, within this pass, whether asset-hub-westend's/asset-hub-rococo's barrier configuration actually permits an arbitrary signed account to execute a bare `TransferAsset` instruction against the uniques/NFTs transactor (as opposed to the transactor only ever being reached through reserve-transfer instructions where `from`/`to` are constrained by other logic, e.g. `WithdrawAsset` + `DepositAsset` pairs that are separately guarded). This is the key open question that determines whether the flaw is live-exploitable versus merely a latent defect in the adapter/trait design that has not yet been triggered because no current runtime configuration issues bare `TransferAsset` for NFTs to untrusted origins.

### Recommendation
1. Extend `nonfungible(s)::Transfer::transfer` to accept an optional/required `check_owner: Option<&AccountId>` parameter (mirroring `Mutate::burn`), and have `pallet-uniques`/`pallet-nfts` implementations enforce it inside `do_transfer`.
2. Update `NonFungibleTransferAdapter`/`NonFungiblesTransferAdapter::transfer_asset` to convert `from` via `AccountIdConverter` and pass it as the required owner check, failing with `XcmError::NoPermission`/`FailedToTransactAsset` if the current owner does not match `from`.
3. Add a regression integration test that calls `T::transfer_asset` with a `from` location that does **not** own the instance and asserts it errors (the existing `test_nft_asset_transactor_works` test only exercises the fully-authorized happy path and would not catch this).

### Proof of Concept
I could not execute a live reproduction in this pass (no terminal/build access in ask-only mode), so this is a code-path analysis, not an executed PoC. A concrete local reproduction that a Devin agent should run:
1. In `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs`, extend `test_nft_asset_transactor_works` (or add a new test) so that: Alice mints/owns nothing, Bob owns `item_id`, and then call `T::transfer_asset(&item_asset, &alice_account_location /* NOT the owner */, &charlie_account_location, &ctx)`.
2. Expected (secure) behavior: this call should fail with a permission/ownership error since Alice does not own the item.
3. Actual current behavior (per code inspection): `NonFungiblesTransferAdapter::transfer_asset` ignores `from` entirely and calls `Assets::transfer(&class, &instance, &destination)` → `pallet_uniques::do_transfer` with a no-op ownership closure → the transfer succeeds, moving Bob's item to Charlie's account without Alice ever owning it or holding an approval.
4. If barrier configuration in the target runtime permits a signed account to submit this `TransferAsset` instruction via `pallet_xcm::execute`, this constitutes a working exploit; verifying that barrier configuration is the remaining step needed to fully confirm live exploitability, which requires running the actual test suite/build that I do not have access to in this mode.

### Citations

**File:** polkadot/xcm/xcm-builder/src/nonfungibles_adapter.rs (L53-76)
```rust
	fn transfer_asset(
		what: &Asset,
		from: &Location,
		to: &Location,
		context: &XcmContext,
	) -> Result<Asset, XcmError> {
		tracing::trace!(
			target: LOG_TARGET,
			?what,
			?from,
			?to,
			?context,
			"transfer_asset",
		);
		// Check we handle this asset.
		let (class, instance) = Matcher::matches_nonfungibles(what)?;
		let destination = AccountIdConverter::convert_location(to)
			.ok_or(MatchError::AccountIdConversionFailed)?;
		Assets::transfer(&class, &instance, &destination).map_err(|e| {
			tracing::debug!(target: LOG_TARGET, ?e, ?class, ?instance, ?destination, "Failed to transfer asset");
			XcmError::FailedToTransactAsset(e.into())
		})?;
		Ok(what.clone())
	}
```

**File:** polkadot/xcm/xcm-builder/src/nonfungibles_adapter.rs (L412-421)
```rust
	fn transfer_asset(
		what: &Asset,
		from: &Location,
		to: &Location,
		context: &XcmContext,
	) -> Result<Asset, XcmError> {
		NonFungiblesTransferAdapter::<Assets, Matcher, AccountIdConverter, AccountId>::transfer_asset(
			what, from, to, context,
		)
	}
```

**File:** polkadot/xcm/xcm-builder/src/nonfungible_adapter.rs (L50-73)
```rust
	fn transfer_asset(
		what: &Asset,
		from: &Location,
		to: &Location,
		context: &XcmContext,
	) -> Result<Asset, XcmError> {
		tracing::trace!(
			target: LOG_TARGET,
			?what,
			?from,
			?to,
			?context,
			"transfer_asset",
		);
		// Check we handle this asset.
		let instance = Matcher::matches_nonfungible(what).ok_or(MatchError::AssetNotHandled)?;
		let destination = AccountIdConverter::convert_location(to)
			.ok_or(MatchError::AccountIdConversionFailed)?;
		NonFungible::transfer(&instance, &destination).map_err(|e| {
			tracing::debug!(target: LOG_TARGET, ?e, ?instance, ?destination, "Failed to transfer non-fungible asset");
			XcmError::FailedToTransactAsset(e.into())
		})?;
		Ok(what.clone())
	}
```

**File:** polkadot/xcm/xcm-builder/src/nonfungible_adapter.rs (L105-111)
```rust
	fn can_reduce_checked(checking_account: AccountId, instance: NonFungible::ItemId) -> XcmResult {
		// This is an asset whose teleports we track.
		let owner = NonFungible::owner(&instance);
		ensure!(owner == Some(checking_account), XcmError::NotWithdrawable);
		ensure!(NonFungible::can_transfer(&instance), XcmError::NotWithdrawable);
		Ok(())
	}
```

**File:** polkadot/xcm/xcm-builder/src/nonfungible_adapter.rs (L377-386)
```rust
	fn transfer_asset(
		what: &Asset,
		from: &Location,
		to: &Location,
		context: &XcmContext,
	) -> Result<Asset, XcmError> {
		NonFungibleTransferAdapter::<NonFungible, Matcher, AccountIdConverter, AccountId>::transfer_asset(
			what, from, to, context,
		)
	}
```

**File:** substrate/frame/uniques/src/impl_nonfungibles.rs (L152-160)
```rust
impl<T: Config<I>, I: 'static> Transfer<T::AccountId> for Pallet<T, I> {
	fn transfer(
		collection: &Self::CollectionId,
		item: &Self::ItemId,
		destination: &T::AccountId,
	) -> DispatchResult {
		Self::do_transfer(collection.clone(), *item, destination.clone(), |_, _| Ok(()))
	}
}
```

**File:** substrate/frame/nfts/src/impl_nonfungibles.rs (L412-419)
```rust
impl<T: Config<I>, I: 'static> Transfer<T::AccountId> for Pallet<T, I> {
	fn transfer(
		collection: &Self::CollectionId,
		item: &Self::ItemId,
		destination: &T::AccountId,
	) -> DispatchResult {
		Self::do_transfer(*collection, *item, destination.clone(), |_, _| Ok(()))
	}
```

**File:** substrate/frame/nfts/src/features/transfer.rs (L82-93)
```rust
		// Retrieve the item details.
		let mut details =
			Item::<T, I>::get(&collection, &item).ok_or(Error::<T, I>::UnknownItem)?;

		// Perform the transfer with custom details using the provided closure.
		with_details(&collection_details, &mut details)?;

		// Update account ownership information.
		Account::<T, I>::remove((&details.owner, &collection, &item));
		Account::<T, I>::insert((&dest, &collection, &item), ());
		let origin = details.owner;
		details.owner = dest;
```

**File:** substrate/frame/nfts/src/lib.rs (L1022-1041)
```rust
		pub fn transfer(
			origin: OriginFor<T>,
			collection: T::CollectionId,
			item: T::ItemId,
			dest: AccountIdLookupOf<T>,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;
			let dest = T::Lookup::lookup(dest)?;

			Self::do_transfer(collection, item, dest, |_, details| {
				if details.owner != origin {
					let deadline =
						details.approvals.get(&origin).ok_or(Error::<T, I>::NoPermission)?;
					if let Some(d) = deadline {
						let block_number = T::BlockNumberProvider::current_block_number();
						ensure!(block_number <= *d, Error::<T, I>::ApprovalExpired);
					}
				}
				Ok(())
			})
```

**File:** substrate/frame/uniques/src/lib.rs (L649-664)
```rust
		pub fn transfer(
			origin: OriginFor<T>,
			collection: T::CollectionId,
			item: T::ItemId,
			dest: AccountIdLookupOf<T>,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;
			let dest = T::Lookup::lookup(dest)?;

			Self::do_transfer(collection, item, dest, |collection_details, details| {
				if details.owner != origin && collection_details.admin != origin {
					let approved = details.approved.take().map_or(false, |i| i == origin);
					ensure!(approved, Error::<T, I>::NoPermission);
				}
				Ok(())
			})
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L1-1)
```rust
// Copyright (C) Parity Technologies (UK) Ltd.
```
