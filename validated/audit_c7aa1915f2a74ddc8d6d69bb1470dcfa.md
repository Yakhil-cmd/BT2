# Analysis Result

## Title
Coretime Region NFTs can be stolen via XCM `TransferAsset` because `NonFungibleTransferAdapter` bypasses pallet-broker's ownership check — ([File: polkadot/xcm/xcm-builder/src/nonfungible_adapter.rs])

## Summary
CVE-2021-39234 describes Apache Ozone allowing an authenticated user who merely *knows the ID* of an existing block to reach it through a request path that skips the normal ACL enforcement. The Polkadot SDK analog is in the XCM `NonFungible` asset-transactor used to move `pallet-broker` Coretime Region NFTs: the `TransferAsset` XCM instruction is routed through `NonFungibleTransferAdapter::transfer_asset`, which never verifies that the XCM `from` location is the actual owner of the referenced `RegionId` before calling the underlying `nonfungible::Transfer::transfer` implementation — which itself unconditionally skips the owner check (`None`).

## Finding Description
`pallet-broker`'s internal transfer primitive, `do_transfer`, only enforces ownership when it is explicitly asked to: [1](#0-0) 

The normal, protected path (e.g. the admin-only `force_transfer` extrinsic, which requires `T::AdminOrigin`) intentionally documents that passing `None` "ignores the previous owner": [2](#0-1) 

However, the same unchecked call is also reachable through the pallet's `nonfungible::Transfer` trait implementation, which is used purely for XCM asset-transactor bookkeeping and *always* passes `None`, i.e. it never checks who is actually authorized to move the item: [3](#0-2) 

This trait implementation is wired into the generic XCM builder adapter `NonFungibleTransferAdapter`, whose `transfer_asset` implementation receives the XCM `from` location, but **never uses it to verify ownership** — it is only used for a trace log, then discarded, before calling `NonFungible::transfer(&instance, &destination)`: [4](#0-3) 

On the coretime-westend runtime, this adapter is configured as the transactor for Broker Regions and included in the live `AssetTransactors` tuple used by the XCM executor: [5](#0-4) 

Crucially, ordinary signed accounts are permitted to execute local XCM programs on this chain (not just receive them from other chains): [6](#0-5) 

Putting this together: any signed, non-privileged account can call `pallet_xcm::execute` with a program containing a `TransferAsset` instruction that (a) pays for execution to satisfy the `AllowTopLevelPaidExecutionFrom<Everything>` barrier, and (b) specifies an `Asset` matching `IsConcrete<BrokerPalletLocation>` with a `NonFungible(AssetInstance::Index(region_id_as_u128))` equal to a **victim's existing `RegionId`**, and any `beneficiary` location. Because the adapter never checks that `from` (the caller's own converted location) is the recorded owner of that Region, `Broker::do_transfer(region_id, None, attacker_account)` executes unconditionally, overwriting the `Regions` storage entry's owner field to the attacker.

This exactly mirrors the CVE's structure: the caller is authenticated but has no privilege over the resource; the resource identifier (`RegionId`/block ID) is the only input needed; a secondary API path (asset-transactor `transfer_asset` vs. the ACL-checked dispatchable path) omits the authorization check that the "normal" path enforces.

## Impact Explanation
Any account that merely observes an existing `RegionId` on-chain (Region IDs, i.e. `(begin, core, mask)`, are public and emitted in events / storage, not secrets) can steal that Coretime Region NFT from its rightful owner without payment, consent, or any privileged role. Coretime Regions represent real, saleable purchase rights (bulk-coretime blockspace allocations) with material value, so this is a direct unauthorized-transfer / theft vulnerability against a live production system (Coretime chains on Polkadot/Kusama). This matches the report's preferred "theft" / "unauthorized dispatch" severity class.

## Likelihood Explanation
The precondition is only "attacker holds a signed account with enough balance to pay XCM execution fees" — no governance, no validator/collator control, no stolen keys. `RegionId`s are discoverable from public chain state/events. The Barrier configuration (`AllowTopLevelPaidExecutionFrom<Everything>`) explicitly permits arbitrary local origins to execute paid XCM programs, so the reachability chain (`pallet_xcm::execute` → `XcmExecutor` → `TransferAsset` → `NonFungibleTransferAdapter::transfer_asset` → `Broker::transfer` → `do_transfer(_, None, _)`) is a direct, always-available call sequence, not a race condition or edge case.

## Recommendation
`NonFungibleTransferAdapter::transfer_asset` (and, more fundamentally, `pallet_broker`'s `nonfungible::Transfer::transfer` implementation) must verify that the `from` location — converted to an `AccountId` via `AccountIdConverter` — matches the current recorded owner of the `RegionId` before calling `do_transfer`. This means passing `Some(from_account)` as `maybe_check_owner` into `do_transfer` instead of unconditionally passing `None`, analogous to the check already performed in `dispatchable_impls.rs`'s owner-checked branches.

## Proof of Concept
I was not able to execute a live PoC in this session (no filesystem/terminal access was used; the investigation was static/code-reading only, consistent with the analysis constraints). The traced call chain, based on reading the actual production wiring, is:

1. Attacker (any signed account, no special role) submits `pallet_xcm::execute` with an XCM program:
   `[WithdrawAsset(fee), BuyExecution{fee, ...}, TransferAsset{ assets: [Asset{ id: Concrete(BrokerPalletLocation), fun: NonFungible(AssetInstance::Index(victim_region_id_u128)) }], beneficiary: attacker_location }]`.
2. `ExecuteXcmOrigin` (`EnsureXcmOrigin<RuntimeOrigin, LocalOriginToLocation>`) converts the attacker's signed origin into their own account `Location` — no ownership of the targeted Region is verified at this stage.
3. `Barrier`'s `AllowTopLevelPaidExecutionFrom<Everything>` passes because the program pays its own fees.
4. `TransferAsset` dispatches to `AssetTransactors` (the `RegionTransactor = NonFungibleAdapter<Broker, ...>` branch), invoking `NonFungibleTransferAdapter::transfer_asset(what, from=attacker_location, to=beneficiary, ...)`.
5. That function calls `Broker::transfer(&victim_region_id, &destination)` → `do_transfer(victim_region_id, None, destination)`, which skips the `ensure!(Some(check_owner) == region.owner, ...)` branch entirely because `maybe_check_owner` is `None`, and overwrites `Regions[victim_region_id].owner = Some(attacker_account)`.

Because I could not run this against a client/test harness in this session, I am reporting the finding as a **traced, code-verified analog with unverified live execution** rather than a confirmed exploited PoC. A background engineering session with filesystem/terminal access would be required to build and run an XCM-simulator or emulated-runtime integration test (e.g. under `cumulus/parachains/runtimes/coretime/coretime-westend/tests/` or `polkadot/xcm/xcm-simulator`) asserting: pre-state `Regions[region_id].owner == victim`, execute the crafted program as `attacker`, and assert post-state `Regions[region_id].owner == attacker` with no `NotOwner` error raised.

### Citations

**File:** substrate/frame/broker/src/dispatchable_impls.rs (L230-243)
```rust
	pub(crate) fn do_transfer(
		region_id: RegionId,
		maybe_check_owner: Option<T::AccountId>,
		new_owner: T::AccountId,
	) -> Result<(), Error<T>> {
		let mut region = Regions::<T>::get(&region_id).ok_or(Error::<T>::UnknownRegion)?;

		if let Some(check_owner) = maybe_check_owner {
			ensure!(Some(check_owner) == region.owner, Error::<T>::NotOwner);
		}

		let old_owner = region.owner;
		region.owner = Some(new_owner);
		Regions::<T>::insert(&region_id, &region);
```

**File:** substrate/frame/broker/src/lib.rs (L1070-1087)
```rust
		/// Transfer a Bulk Coretime Region to a new owner, ignoring the previous owner.
		///
		/// This can also be used to recover regions that have been "burned" (e.g., from an
		/// XCM reserve transfer).
		///
		/// - `origin`: Must be Root or pass `AdminOrigin`.
		/// - `region_id`: The Region whose ownership should change.
		/// - `new_owner`: The new owner for the Region.
		#[pallet::call_index(28)]
		pub fn force_transfer(
			origin: OriginFor<T>,
			region_id: RegionId,
			new_owner: T::AccountId,
		) -> DispatchResult {
			T::AdminOrigin::ensure_origin_or_root(origin)?;
			Self::do_transfer(region_id, None, new_owner)?;
			Ok(())
		}
```

**File:** substrate/frame/broker/src/nonfungible_impl.rs (L49-53)
```rust
impl<T: Config> Transfer<T::AccountId> for Pallet<T> {
	fn transfer(item: &Self::ItemId, dest: &T::AccountId) -> DispatchResult {
		Self::do_transfer((*item).into(), None, dest.clone()).map_err(Into::into)
	}
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

**File:** cumulus/parachains/runtimes/coretime/coretime-westend/src/xcm_config.rs (L103-118)
```rust
/// Means for transacting coretime regions on this chain.
pub type RegionTransactor = NonFungibleAdapter<
	// Use this non-fungible implementation:
	Broker,
	// This adapter will handle coretime regions from the broker pallet.
	IsConcrete<BrokerPalletLocation>,
	// Convert an XCM Location into a local account id:
	LocationToAccountId,
	// Our chain's account ID type (we can't get away without mentioning it explicitly):
	AccountId,
	// We don't track any teleports.
	(),
>;

/// Means for transacting assets on this chain.
pub type AssetTransactors = (FungibleTransactor, RegionTransactor);
```

**File:** cumulus/parachains/runtimes/coretime/coretime-westend/src/xcm_config.rs (L306-316)
```rust
impl pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	// We want to disallow users sending (arbitrary) XCM programs from this chain.
	type SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, ()>;
	type XcmRouter = XcmRouter;
	// We support local origins dispatching XCM executions.
	type ExecuteXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalOriginToLocation>;
	type XcmExecuteFilter = Everything;
	type XcmExecutor = XcmExecutor<XcmConfig>;
	type XcmTeleportFilter = Everything;
	type XcmReserveTransferFilter = Everything;
```
