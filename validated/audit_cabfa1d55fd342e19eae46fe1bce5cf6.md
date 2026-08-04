Based on my research, I found a plausible analog but cannot confirm exploitability with full confidence given remaining index limitations.

### Title
Unsigned-origin (`EnsureNone`) authorization for privileged sovereign-account migration call - ([File: system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs])

### Summary
The reported Comet bug is a missing-access-control issue: a state-mutating function intended to be admin-only was reachable by any caller due to absent origin/authorization checks. Searching this repo for the analogous pattern — a privileged call whose origin check is effectively too permissive — surfaces `pallet_ah_ops::Pallet::translate_para_sovereign_child_to_sibling_derived`, which migrates native balance, staked balances, and configured assets between accounts and is gated by `T::MigrateOrigin::ensure_origin(origin)?` [1](#0-0) . On Asset Hub Polkadot this origin is configured strictly (`EitherOfDiverse<EnsureRoot<AccountId>, EnsureXcm<IsFellowshipVoice<FellowshipLocation>>>`) [2](#0-1) , but on Asset Hub Kusama the same call's `MigrateOrigin` is configured as `EnsureNone<AccountId>` [3](#0-2) .

### Finding Description
`EnsureNone` only succeeds against `RawOrigin::None`, which in FRAME is the origin used for unsigned extrinsics/inherents rather than a normal signed caller. Configuring `MigrateOrigin = EnsureNone<AccountId>` on Kusama's Asset Hub therefore removes the "signed caller must be authorized" check that exists on Polkadot's Asset Hub, and instead relies entirely on the transaction-pool/validation layer to decide who may submit an unsigned extrinsic invoking this call.

However, I could not find a `ValidateUnsigned` implementation anywhere in the repository (including in `pallet_ah_ops`) via `grep_search` [4](#0-3) . Without a `ValidateUnsigned` implementation registered for `pallet_ah_ops::Call::translate_para_sovereign_child_to_sibling_derived`, FRAME's default unsigned-transaction validation (`UnknownTransaction::NoUnsignedValidator`) would reject any submitted unsigned extrinsic calling it, meaning the `RawOrigin::None` path would normally be unreachable through the ordinary extrinsic pipeline. I was not able to fully verify, within the available index, whether this call is dispatched some other way (e.g., as part of a `ParachainSystem` inherent path, an `on_initialize`/migration hook, or a XCM-derived origin conversion) that would make `RawOrigin::None` reachable in practice — that would require inspecting the full `pallet_ah_ops` module, its `on_initialize`/hooks, and how the Kusama Asset Hub's inherent/extrinsic pipeline is wired, which the index did not surface completely.

### Impact Explanation
If `RawOrigin::None` is reachable for this call on Kusama's Asset Hub (e.g. via some inherent-like invocation path not requiring authorization), an attacker could invoke `translate_para_sovereign_child_to_sibling_derived` to move native DOT/KSM balance, staked balances, and configured assets from an arbitrary `old_account` to an arbitrary `new_account` of their choosing, directly analogous to the Comet bug where a privileged operation was executable by an unauthorized party. This would constitute unauthorized manipulation of parachain sovereign account balances during/around the Asset Hub Migration window.

### Likelihood Explanation
Likelihood is uncertain and cannot be confirmed as "unprivileged attacker reachable" without further evidence that unsigned extrinsics invoking this specific call would pass block-building/transaction-pool validation. Given the absence of any `ValidateUnsigned` implementation found in the codebase, the default FRAME behavior would reject such unsigned calls, which argues against practical reachability — this is the standard mechanism that prevents `EnsureNone`-gated calls from being freely invoked by arbitrary accounts.

### Recommendation
Given the ambiguity, the concrete, low-risk recommendation is: verify whether `EnsureNone<AccountId>` is the intended, safe configuration for `MigrateOrigin` on Kusama's Asset Hub (e.g., because this call is only meant to be invoked as part of a controlled inherent/migration-only pathway with no `ValidateUnsigned` making it de facto uncallable), and if it is not provably restricted to a trusted invocation path, align it with the Polkadot configuration (`EitherOfDiverse<EnsureRoot<AccountId>, EnsureXcm<IsFellowshipVoice<FellowshipLocation>>>`) or an equivalent restrictive origin, and add explicit tests asserting that arbitrary unsigned/signed callers cannot successfully dispatch this extrinsic.

### Proof of Concept
Not conclusively demonstrable from the available code: reproducing exploitation would require constructing an unsigned extrinsic dispatching `pallet_ah_ops::Call::translate_para_sovereign_child_to_sibling_derived` against the Kusama Asset Hub runtime and confirming whether it passes transaction validation and executes, given the absence of a discoverable `ValidateUnsigned` implementation in this codebase. I could not verify this end-to-end within the current investigation, so this finding should be treated as a configuration discrepancy worth verifying by a developer with full repository/runtime access rather than a confirmed, immediately-exploitable vulnerability.

### Citations

**File:** pallets/ah-ops/src/lib.rs (L279-411)
```rust
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Unreserve the deposit that was taken for creating a crowdloan.
		///
		/// This can be called by any signed origin. It unreserves the lease deposit on the account
		/// that won the lease auction. It can be unreserved once all leases expired. Note that it
		/// will be called automatically from `withdraw_crowdloan_contribution` for the matching
		/// crowdloan account.
		///
		/// Solo bidder accounts that won lease auctions can use this to unreserve their amount.
		#[pallet::call_index(0)]
		#[pallet::weight(<T as Config>::WeightInfo::unreserve_lease_deposit())]
		pub fn unreserve_lease_deposit(
			origin: OriginFor<T>,
			block: BlockNumberFor<T>,
			depositor: Option<T::AccountId>,
			para_id: ParaId,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			let depositor = depositor.unwrap_or(sender);

			Self::do_unreserve_lease_deposit(block, depositor, para_id).map_err(Into::into)
		}

		/// Withdraw the contribution of a finished crowdloan.
		///
		/// A crowdloan contribution can be withdrawn if either:
		/// - The crowdloan failed to in an auction and timed out
		/// - Won an auction and all leases expired
		///
		/// Can be called by any signed origin.
		#[pallet::call_index(1)]
		#[pallet::weight(<T as Config>::WeightInfo::withdraw_crowdloan_contribution())]
		pub fn withdraw_crowdloan_contribution(
			origin: OriginFor<T>,
			block: BlockNumberFor<T>,
			depositor: Option<T::AccountId>,
			para_id: ParaId,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			let depositor = depositor.unwrap_or(sender);

			Self::do_withdraw_crowdloan_contribution(block, depositor, para_id).map_err(Into::into)
		}

		/// Unreserve the deposit that was taken for creating a crowdloan.
		///
		/// This can be called once either:
		/// - The crowdloan failed to win an auction and timed out
		/// - Won an auction, all leases expired and all contributions are withdrawn
		///
		/// Can be called by any signed origin. The condition that all contributions are withdrawn
		/// is in place since the reserve acts as a storage deposit.
		#[pallet::call_index(2)]
		#[pallet::weight(<T as Config>::WeightInfo::unreserve_crowdloan_reserve())]
		pub fn unreserve_crowdloan_reserve(
			origin: OriginFor<T>,
			block: BlockNumberFor<T>,
			depositor: Option<T::AccountId>,
			para_id: ParaId,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			let depositor = depositor.unwrap_or(sender);

			Self::do_unreserve_crowdloan_reserve(block, depositor, para_id).map_err(Into::into)
		}

		/// Transfer the balance from the pre-migration treasury account to the post-migration
		/// treasury account.
		///
		/// This call can only be called after the migration is completed.
		#[pallet::call_index(3)]
		#[pallet::weight({
			Weight::from_parts(100_000_000, 9000)
				.saturating_add(T::DbWeight::get().reads_writes(2, 2))
		})]
		pub fn transfer_to_post_migration_treasury(
			origin: OriginFor<T>,
			asset_id: Box<<T::Fungibles as FungiblesInspect<T::AccountId>>::AssetId>,
		) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;

			ensure!(T::MigrationCompletion::get(), Error::<T>::MigrationNotCompleted);

			let pre_migration_account = T::TreasuryPreMigrationAccount::get();
			let post_migration_account = T::TreasuryPostMigrationAccount::get();

			let balance =
				<T as Config>::Fungibles::balance(*asset_id.clone(), &pre_migration_account);
			ensure!(balance > 0, Error::<T>::ZeroBalance);

			<T as Config>::Fungibles::transfer(
				*asset_id,
				&pre_migration_account,
				&post_migration_account,
				balance,
				Preservation::Expendable,
			)?;

			Ok(Pays::No.into())
		}

		/// Translate recursively derived parachain sovereign child account to its sibling.
		///
		/// Uses the same derivation path on the sibling. The old and new account arguments are only
		/// witness data to ensure correct usage. Can only be called by the `MigrateOrigin`.
		///
		/// This migrates:
		/// - Native DOT balance
		/// - All assets listed in `T::RelevantAssets`
		/// - Staked balances
		///
		/// Things like non-relevant assets or vested transfers may remain on the old account.
		#[pallet::call_index(4)]
		#[pallet::weight(Weight::from_parts(100_000_000, 9000)
				.saturating_add(T::DbWeight::get().reads_writes(20, 20)))]
		pub fn translate_para_sovereign_child_to_sibling_derived(
			origin: OriginFor<T>,
			para_id: u16,
			derivation_path: Vec<u16>,
			old_account: T::AccountId,
			new_account: T::AccountId,
		) -> DispatchResult {
			T::MigrateOrigin::ensure_origin(origin)?;

			Self::do_translate_para_sovereign_child_to_sibling_derived(
				para_id,
				derivation_path,
				old_account,
				new_account,
			)
			.map_err(Into::into)
		}
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs (L1433-1434)
```rust
	type MigrateOrigin =
		EitherOfDiverse<EnsureRoot<AccountId>, EnsureXcm<IsFellowshipVoice<FellowshipLocation>>>;
```

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs (L1374-1387)
```rust
impl pallet_ah_ops::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type Fungibles = NativeAndAssets;
	type RcBlockNumberProvider = RelaychainDataProvider<Runtime>;
	type WeightInfo = weights::pallet_ah_ops::WeightInfo<Runtime>;
	type MigrationCompletion = ConstBool<true>;
	type TreasuryPreMigrationAccount = xcm_config::PreMigrationRelayTreasuryPalletAccount;
	type TreasuryPostMigrationAccount = xcm_config::PostMigrationTreasuryAccount;
	type MigrationStartBlock = MigrationStartBlock;
	type MigrationEndBlock = MigrationEndBlock;
	type AssetId = Location;
	type RelevantAssets = ();
	type MigrateOrigin = EnsureNone<AccountId>;
```
