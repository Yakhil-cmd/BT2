## Analysis Result

I found a direct analog to the reported vulnerability class in `pallets/ah-ops/src/lib.rs`. Several permissionlessly-callable extrinsics that move real user funds (crowdloan/lease deposits, treasury balances) complete successfully without emitting any event, mirroring the "lack of event emission after sensitive actions" pattern from the `FundingRateApplier._getLatestFundingRate` report.

### Title
Missing event emission on successful crowdloan/lease fund transfers and treasury migration transfer - (File: pallets/ah-ops/src/lib.rs)

### Summary
The `pallet_ah_ops` extrinsics `unreserve_lease_deposit`, `withdraw_crowdloan_contribution`, `unreserve_crowdloan_reserve`, and `transfer_to_post_migration_treasury` move balances of user or treasury funds but only emit an `Event` in defensive/error branches, never on the successful, expected execution path [1](#0-0) .

### Finding Description
`do_unreserve_lease_deposit` unreserves a depositor's balance and only calls `Self::deposit_event(Event::LeaseUnreserveRemaining {...})` inside the `if remaining > 0` defensive branch, which is only hit when the unreserve fails to release the full amount — an anomaly path, not the normal success path [2](#0-1) . The same pattern repeats in `do_unreserve_crowdloan_reserve` [3](#0-2) . `do_withdraw_crowdloan_contribution` transfers the contribution from the crowdloan pot to the depositor and reactivates the currency, but emits no event at all on success [4](#0-3) . Likewise `transfer_to_post_migration_treasury` moves the entire pre-migration treasury balance of an asset to the post-migration treasury account and returns `Ok(Pays::No.into())` without emitting any event [5](#0-4) . By contrast, `do_translate_para_sovereign_child_to_sibling_derived` (also in this pallet) correctly emits `Event::SovereignMigrated` after performing its balance/asset transfers, showing the pallet's own convention that fund-moving operations should be observable via events [6](#0-5) .

### Impact Explanation
Off-chain indexers, wallets, and monitoring tooling that rely on pallet events to track balance-affecting activity (as documented for the migration process itself, which does emit `AssetHubMigrationStarted`/`Finished` events [7](#0-6) ) cannot reliably detect or notify users when their crowdloan contributions/lease deposits are withdrawn/unreserved, or when large treasury transfers occur. This is a low-severity observability/tracking gap rather than a fund-safety issue — no funds are lost or misdirected, but auditability and off-chain reconciliation of these one-time migration-cleanup operations is impaired.

### Likelihood Explanation
These calls are permissionless (`ensure_signed(origin)?`) and are documented as callable by "any signed origin" [8](#0-7) , so any unprivileged user with an eligible crowdloan/lease deposit will trigger this gap during normal, expected usage — this is not a theoretical edge case, it is the default success path for a legitimate migration-cleanup feature.

### Recommendation
Emit a dedicated event (e.g. `LeaseUnreserved`, `CrowdloanContributionWithdrawn`, `CrowdloanReserveUnreserved`, `TreasuryTransferred`) on the successful completion of `do_unreserve_lease_deposit`, `do_withdraw_crowdloan_contribution`, `do_unreserve_crowdloan_reserve`, and `transfer_to_post_migration_treasury`, in addition to the existing defensive-only events, so off-chain clients can track these fund movements.

### Proof of Concept
Call `pallet_ah_ops::withdraw_crowdloan_contribution(origin, block, None, para_id)` with a valid, matured crowdloan contribution recorded in `RcCrowdloanContribution`; the extrinsic succeeds (funds move from pot to depositor per `do_withdraw_crowdloan_contribution` [4](#0-3) ) but inspecting the resulting block's events shows no `pallet_ah_ops::Event` was deposited, confirming off-chain observers cannot detect the withdrawal from events alone.

### Citations

**File:** pallets/ah-ops/src/lib.rs (L281-301)
```rust
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
```

**File:** pallets/ah-ops/src/lib.rs (L355-379)
```rust
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
```

**File:** pallets/ah-ops/src/lib.rs (L414-435)
```rust
	impl<T: Config> Pallet<T> {
		pub fn do_unreserve_lease_deposit(
			block: BlockNumberFor<T>,
			depositor: T::AccountId,
			para_id: ParaId,
		) -> Result<(), Error<T>> {
			ensure!(block <= T::RcBlockNumberProvider::current_block_number(), Error::<T>::NotYet);
			let balance = RcLeaseReserve::<T>::take((block, para_id, &depositor))
				.ok_or(Error::<T>::NoLeaseReserve)?;

			let remaining = <T as Config>::Currency::unreserve(&depositor, balance);
			if remaining > 0 {
				defensive!("Should be able to unreserve all");
				Self::deposit_event(Event::LeaseUnreserveRemaining {
					depositor,
					remaining,
					para_id,
				});
			}

			Ok(())
		}
```

**File:** pallets/ah-ops/src/lib.rs (L437-468)
```rust
		pub fn do_withdraw_crowdloan_contribution(
			block: BlockNumberFor<T>,
			depositor: T::AccountId,
			para_id: ParaId,
		) -> Result<(), Error<T>> {
			ensure!(block <= T::RcBlockNumberProvider::current_block_number(), Error::<T>::NotYet);
			let (pot, contribution) =
				RcCrowdloanContribution::<T>::take((block, para_id, &depositor))
					.ok_or(Error::<T>::NoCrowdloanContribution)?;

			// Maybe this is the first one to withdraw and we need to unreserve it from the pot
			match Self::do_unreserve_lease_deposit(block, pot.clone(), para_id) {
				Ok(()) => (),
				Err(Error::<T>::NoLeaseReserve) => (), // fine
				Err(e) => return Err(e),
			}

			// Ideally this does not fail. But if it does, then we keep it for manual inspection.
			let transferred = <<T as Config>::Currency as FungibleMutate<_>>::transfer(
				&pot,
				&depositor,
				contribution,
				Preservation::Expendable,
			)
			.defensive()
			.map_err(|_| Error::<T>::FailedToWithdrawCrowdloanContribution)?;
			defensive_assert!(transferred == contribution);
			// Need to reactivate since we deactivated it here https://github.com/paritytech/polkadot-sdk/blob/04847d515ef56da4d0801c9b89a4241dfa827b33/polkadot/runtime/common/src/crowdloan/mod.rs#L793
			<<T as Config>::Currency as Currency<_>>::reactivate(transferred);

			Ok(())
		}
```

**File:** pallets/ah-ops/src/lib.rs (L470-494)
```rust
		pub fn do_unreserve_crowdloan_reserve(
			block: BlockNumberFor<T>,
			depositor: T::AccountId,
			para_id: ParaId,
		) -> Result<(), Error<T>> {
			ensure!(block <= T::RcBlockNumberProvider::current_block_number(), Error::<T>::NotYet);
			ensure!(
				Self::contributions_withdrawn(block, para_id),
				Error::<T>::ContributionsRemaining
			);
			let amount = RcCrowdloanReserve::<T>::take((block, para_id, &depositor))
				.ok_or(Error::<T>::NoCrowdloanReserve)?;

			let remaining = <T as Config>::Currency::unreserve(&depositor, amount);
			if remaining > 0 {
				defensive!("Should be able to unreserve all");
				Self::deposit_event(Event::CrowdloanUnreserveRemaining {
					depositor,
					remaining,
					para_id,
				});
			}

			Ok(())
		}
```

**File:** pallets/ah-ops/src/lib.rs (L683-688)
```rust
			Self::deposit_event(Event::SovereignMigrated {
				para_id,
				from: from.clone(),
				to: to.clone(),
				derivation_path,
			});
```

**File:** pallets/rc-migrator/README.md (L27-40)
```markdown
The migration will begin to run from the fixed block number and emit the following events to notify of this:

- `pallet_rc_migrator::AssetHubMigrationStarted` on the Relay Chain
- `pallet_ah_migrator::AssetHubMigrationStarted` on the Asset Hub

You can listen for these events to know whether the migration is ongoing.

The first thing the migration does, is to lock functionality on the Relay and Asset Hub. the locking
happens to ensure that no changes interfere with the migration.

Once it is done, two more events are emitted, respectively:

- `pallet_rc_migrator::AssetHubMigrationFinished` on the Relay Chain
- `pallet_ah_migrator::AssetHubMigrationFinished` on the Asset Hub
```
