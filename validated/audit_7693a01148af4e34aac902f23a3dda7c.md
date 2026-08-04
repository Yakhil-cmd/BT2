### Title
Unbounded `Bounties`/`ChildBounties` iteration in a single-block `on_runtime_upgrade` migration can exceed the block weight/proof-size limit - (File: `system-parachains/asset-hubs/asset-hub-kusama/src/migrations.rs`, `system-parachains/asset-hubs/asset-hub-polkadot/src/migrations.rs`)

### Summary
`MigrateBountyAccountAssets` iterates over *all* entries of `pallet_multi_asset_bounties::Bounties` and `pallet_multi_asset_bounties::ChildBounties` inside a single-block `OnRuntimeUpgrade::on_runtime_upgrade()` hook, performing multiple asset transfers per bounty/child-bounty. This is the same architectural pattern flagged in the external Compound report: an unbounded storage collection (`allMarkets`) is fully iterated inside one execution context with a fixed gas/weight budget (`claimComp()` / `_addMarketInternal()`), so once the collection grows large enough the call becomes irreversibly too expensive to execute. [1](#0-0) 

### Finding Description
`MigrateBountyAccountAssets` is registered as one of the `Unreleased` `SingleBlockMigrations` that run atomically during the next runtime upgrade: [2](#0-1) 

Its `on_runtime_upgrade` implementation loops over every key in `pallet_multi_asset_bounties::Bounties::<Runtime>::iter_keys()` and every key in `ChildBounties::<Runtime>::iter_keys()`, calling `Transferer::force_transfer_all_assets` for each one and accumulating `db_weight.reads_writes(...)` for weight accounting: [3](#0-2) 

There is no bound on the number of `Bounties` entries iterated — `pallet_multi_asset_bounties::Config` caps only the number of *active child bounties per parent* via `MaxActiveChildBountyCount` (100), not the total number of bounties or child bounties system-wide: [4](#0-3) 

Because bounties accumulate historically (bounty IDs are never removed from `Bounties`/`ChildBounties` storage once created, they just transition through states), and the migration is a normal weighted `on_runtime_upgrade` running fully within one block, this is structurally analogous to Compound's `allMarkets` loop in `claimComp()`: an ever-growing, ungoverned-in-size collection is walked in full inside a single fixed-weight execution unit.

### Impact Explanation
If the number of accumulated bounty/child-bounty entries grows large enough that the accrued weight of `MigrateBountyAccountAssets` (computed as `2 * assets_per_bounty` reads/writes per entry, times the entry count) exceeds the block's max weight/proof-size limit, the runtime upgrade extrinsic itself could fail to execute or push the block over its weight limit, jeopardizing the ability to safely apply future runtime upgrades on Asset Hub Polkadot/Kusama. Unlike Compound's `claimComp()` (a permissionless call that degrades over time), this specific migration only runs once during a runtime upgrade, so the practical impact is limited to that one-time execution rather than an ongoing DoS on user-facing calls.

### Likelihood Explanation
Low-to-moderate. Bounty/child-bounty counts on Asset Hub are governance-gated (bounties are created via Treasury spend origins), so an unprivileged attacker cannot directly spam entries the way the "trusted-role compromise required" disqualifier describes — but this mirrors the original report's own finding, where Compound market additions are also admin-gated, and the client still acknowledged it as a legitimate concern rather than dismissing it. Given current realistic bounty counts on Polkadot/Kusama Asset Hub, this migration is unlikely to hit block weight limits today; the pattern is a latent scalability risk, not an immediately exploitable vulnerability by an unprivileged actor.

### Recommendation
Convert `MigrateBountyAccountAssets` into a multi-block migration (using the `MbmMigrations` / `SteppedMigration` infrastructure already used elsewhere in this file, e.g. `ForeignAssetsReservesMigration`) that processes bounties/child-bounties in bounded batches across multiple blocks, rather than iterating the entire storage map in one `on_runtime_upgrade` call. As a lighter alternative, add an explicit pre-upgrade check (`try-runtime` `pre_upgrade`) asserting the total number of `Bounties` + `ChildBounties` entries stays below a weight-benchmarked safe threshold before allowing the migration to ship.

### Proof of Concept
Not applicable as a live exploit — this is a governance/upgrade-time scalability issue, not an attacker-triggerable call. The root cause is demonstrated structurally: `MigrateBountyAccountAssets::on_runtime_upgrade` at [1](#0-0)  performs `O(n)` unbounded iteration and per-item weight accrual over `pallet_multi_asset_bounties::Bounties`/`ChildBounties`, with no cap on total collection size (`MaxActiveChildBountyCount` only bounds children per parent, not the global count) as configured at [5](#0-4) . A test/benchmark could seed the storage with a synthetically large number of bounty entries and observe the accumulated weight of `on_runtime_upgrade` approach or exceed `BlockWeights::max_block`.

### Citations

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/migrations.rs (L98-128)
```rust
pub struct MigrateBountyAccountAssets;
impl frame_support::traits::OnRuntimeUpgrade for MigrateBountyAccountAssets {
	fn on_runtime_upgrade() -> frame_support::weights::Weight {
		use frame_support::traits::Get;
		use pallet_bounties::TransferAllAssets;
		use sp_runtime::traits::AccountIdConversion;

		let pallet_id = <Runtime as pallet_treasury::Config>::PalletId::get();
		let assets_per_bounty = crate::treasury::BountyRelevantAssets::get().len() as u64;

		type Transferer = <Runtime as pallet_bounties::Config>::TransferAllAssets;

		let db_weight = <Runtime as frame_system::Config>::DbWeight::get();
		let mut weight = frame_support::weights::Weight::zero();

		for bounty_id in pallet_multi_asset_bounties::Bounties::<Runtime>::iter_keys() {
			// Old: `&str "mbt"` (length-prefixed encoding).
			let old: crate::AccountId = pallet_id.into_sub_account_truncating(("mbt", bounty_id));
			// New: `[u8; 3] *b"mbt"` (raw 3 bytes).
			let new: crate::AccountId = pallet_id.into_sub_account_truncating((
				pallet_multi_asset_bounties::BountyAccountPrefix::get(),
				bounty_id,
			));
			let _ = Transferer::force_transfer_all_assets(&old, &new);
			// `TransferAllFungibles` iterates the relevant assets twice and does at
			// most one read + one write per asset.
			weight = weight.saturating_add(
				db_weight.reads_writes(2 * assets_per_bounty, 2 * assets_per_bounty),
			);
		}

```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/migrations.rs (L149-176)
```rust
/// Unreleased migrations. Add new ones here:
pub type Unreleased = (
	// no-op if member has no trapped balance, so second run is safe.
	pallet_nomination_pools::migration::unversioned::ClaimTrappedBalance<
		Runtime,
		TrappedBalanceMember,
	>,
	RemoveAhMigratorPallet,
	// Remove an old staking value.
	crate::staking::RemoveMarchTIValue,
	cumulus_pallet_xcmp_queue::migration::v6::MigrateV5ToV6<Runtime>,
	cumulus_pallet_parachain_system::migration::Migration<Runtime>,
	// DAP V1->V2: seed `BudgetAllocation` and `LastIssuanceTimestamp`, credit a one-shot
	// catch-up drip. Required when moving staking to non-minting mode (see SDK PR #11616).
	pallet_dap::migrations::MigrateV1ToV2<
		Runtime,
		DapLastIssuanceTimestamp,
		DefaultDapBudget,
		crate::dynamic_params::staking_election::MaxEraDuration,
	>,
	MigrateBountyAccountAssets,
);

/// Migrations/checks that do not need to be versioned and can run on every update.
pub type Permanent = pallet_xcm::migration::MigrateToLatestXcmVersion<Runtime>;

/// All single block migrations that will run on the next runtime upgrade.
pub type SingleBlockMigrations = (Unreleased, Permanent);
```

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/migrations.rs (L95-131)
```rust
		let db_weight = <crate::Runtime as frame_system::Config>::DbWeight::get();
		let mut weight = frame_support::weights::Weight::zero();

		for bounty_id in pallet_multi_asset_bounties::Bounties::<crate::Runtime>::iter_keys() {
			// Old: `&str "mbt"` (length-prefixed encoding).
			let old: crate::AccountId = pallet_id.into_sub_account_truncating(("mbt", bounty_id));
			// New: `[u8; 3] *b"mbt"` (raw 3 bytes).
			let new: crate::AccountId = pallet_id.into_sub_account_truncating((
				pallet_multi_asset_bounties::BountyAccountPrefix::get(),
				bounty_id,
			));
			let _ = Transferer::force_transfer_all_assets(&old, &new);
			// `TransferAllFungibles` iterates the relevant assets twice and does at
			// most one read + one write per asset.
			weight = weight.saturating_add(
				db_weight.reads_writes(2 * assets_per_bounty, 2 * assets_per_bounty),
			);
		}

		for (parent_id, child_id) in
			pallet_multi_asset_bounties::ChildBounties::<crate::Runtime>::iter_keys()
		{
			let old: crate::AccountId =
				pallet_id.into_sub_account_truncating(("mcb", parent_id, child_id));
			let new: crate::AccountId = pallet_id.into_sub_account_truncating((
				pallet_multi_asset_bounties::ChildBountyAccountPrefix::get(),
				parent_id,
				child_id,
			));
			let _ = Transferer::force_transfer_all_assets(&old, &new);
			weight = weight.saturating_add(
				db_weight.reads_writes(2 * assets_per_bounty, 2 * assets_per_bounty),
			);
		}

		weight
	}
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/treasury.rs (L124-151)
```rust
parameter_types! {
	pub const MaxActiveChildBountyCount: u32 = 100;
	pub const ChildBountyValueMinimum: Balance = BountyValueMinimum::get() / 10;
}

impl pallet_child_bounties::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type MaxActiveChildBountyCount = MaxActiveChildBountyCount;
	type ChildBountyValueMinimum = ChildBountyValueMinimum;
	type WeightInfo = weights::pallet_child_bounties::WeightInfo<Runtime>;
}

parameter_types! {
	pub const MultiAssetCuratorHoldReason: RuntimeHoldReason =
		RuntimeHoldReason::MultiAssetBounties(pallet_multi_asset_bounties::HoldReason::CuratorDeposit);
}

impl pallet_multi_asset_bounties::Config for Runtime {
	type Balance = Balance;
	type RejectOrigin = EitherOfDiverse<EnsureRoot<AccountId>, Treasurer>;
	type SpendOrigin = TreasurySpender;
	type AssetKind = VersionedLocatableAsset;
	type Beneficiary = VersionedLocatableAccount;
	type BeneficiaryLookup = IdentityLookup<Self::Beneficiary>;
	type BountyValueMinimum = BountyValueMinimum;
	type ChildBountyValueMinimum = ChildBountyValueMinimum;
	type MaxActiveChildBountyCount = MaxActiveChildBountyCount;
	type WeightInfo = weights::pallet_multi_asset_bounties::WeightInfo<Runtime>;
```
