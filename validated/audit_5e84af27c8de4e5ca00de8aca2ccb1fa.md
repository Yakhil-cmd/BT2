### Title
Permissionless `unreserve_lease_deposit`/`unreserve_crowdloan_reserve` can strand solo-bidder sovereign-account deposits on stale "para"-prefixed accounts after governance runs `translate_para_sovereign_child_to_sibling_derived` - (File: pallets/ah-ops/src/lib.rs)

### Summary
`unreserve_lease_deposit`, `withdraw_crowdloan_contribution`, and `unreserve_crowdloan_reserve` are permissionless extrinsics that let any signed caller pick an arbitrary `depositor` account to unreserve balance on [1](#0-0) . For "solo bidder" lease/crowdloan deposits, `depositor` can legitimately be a parachain's `para`-prefixed sovereign account, as documented in the storage docs [2](#0-1) . Separately, the privileged `translate_para_sovereign_child_to_sibling_derived`/`do_translate_para_sovereign_child_to_sibling_derived` moves only the free/reducible DOT and relevant fungible balances (never touching `RcLeaseReserve`/`RcCrowdloanReserve`/`RcCrowdloanContribution`) from the old `para`-prefixed account to the new `sibl`-prefixed sibling account [3](#0-2) . Because the two code paths never cross-check each other, any user can permissionlessly call `unreserve_lease_deposit`/`unreserve_crowdloan_reserve` with `depositor` set to a `para`-account whose sovereign migration has already run, moving reserved balance into free balance on an account that Asset Hub's XCM location converter no longer recognizes as anyone's sovereign account (AH uses `SiblingParachainConvertsVia`/`sibl`, not `ChildParachainConvertsVia`/`para`, for sibling paras) — permanently stranding those funds.

### Finding Description
- `RcLeaseReserve`/`RcCrowdloanReserve` entries are keyed by `(block, para_id, account)`, and the pallet's own documentation states the account "can either be a crowdloan account or a solo bidder" — i.e. it can be the parachain's own sovereign account [2](#0-1) .
- `unreserve_lease_deposit`/`unreserve_crowdloan_reserve` are dispatchable by `ensure_signed` (any signed origin) and accept an optional `depositor` override that need not match the caller [4](#0-3) [5](#0-4) .
- `do_unreserve_lease_deposit`/`do_unreserve_crowdloan_reserve` simply call `Currency::unreserve(&depositor, balance)`, converting reserved balance into free balance on that exact `depositor` account, with no destination redirection check [6](#0-5) [7](#0-6) .
- `do_translate_para_sovereign_child_to_sibling_derived` (governance-only, `MigrateOrigin`) migrates the reducible free balance, relevant fungibles, and staking ledger from the `para`-prefixed sovereign account to the `sibl`-prefixed one, but never inspects or drains `RcLeaseReserve`/`RcCrowdloanReserve`/`RcCrowdloanContribution` for that account [8](#0-7) .
- Once this translation has executed for a given `para_id`/derivation path, there is no enforced re-run: any later permissionless unreserve of that para's residual reserved deposit deposits funds as free balance on the abandoned old `para`-account, which is not recognized by Asset Hub's `SiblingParachainConvertsVia` origin-conversion (only `sibl`-prefixed accounts are), leaving the funds without a controllable owner.
- No check anywhere ties `unreserve_lease_deposit`/`withdraw_crowdloan_contribution`/`unreserve_crowdloan_reserve` to whether `translate_para_sovereign_child_to_sibling_derived` has already run for the same `para_id`, and vice versa — the two subsystems disagree about which account is now the "rightful" one to receive value.
- Attacker-controlled inputs: any signed account can choose `block` (any block number ≤ current relay block), `depositor` (the target `para`-sovereign account, publicly derivable via `para_sov_child`), and `para_id`, and can wrap several such calls in `Utility::batch_all` to atomically drain and strand multiple entries for a given para in one transaction.

### Impact Explanation
This enables a griefing/fund-freeze vector: an unprivileged user can, after governance's one-time sovereign-account translation for a parachain, permissionlessly unreserve that parachain's still-outstanding lease/crowdloan deposit, converting it into free balance sitting on a stale, XCM-unreachable `para`-prefixed account. Since no signature key or recognized XCM origin exists for that account post-migration, the funds become permanently frozen/misdelivered relative to the intended sibling sovereign account — matching the "Critical: permanent freeze or misdelivery of migrated user funds" impact category.

### Likelihood Explanation
Requires that (a) a parachain acted as a solo lease bidder with a `para`-prefixed sovereign account still holding a reserved deposit, and (b) governance has already executed `translate_para_sovereign_child_to_sibling_derived` for that para before the deposit's unreserve condition (`block`) triggers. This ordering is plausible during the Asset Hub migration rollout, where these two operations are performed independently by different actors/scripts with no code-level synchronization; the unreserve calls themselves require no privilege and are fully attacker/anyone triggerable once the block condition is met. The bug is repeatable for any affected `para_id` and does not depend on race conditions beyond call ordering, which is easily observable on-chain.

### Recommendation
Cross-link the two subsystems: either (1) have `do_translate_para_sovereign_child_to_sibling_derived` also drain/redirect any outstanding `RcLeaseReserve`/`RcCrowdloanReserve`/`RcCrowdloanContribution` entries for the `from` account to the `to` account (or explicitly reject translation while such entries exist), or (2) make `unreserve_lease_deposit`/`unreserve_crowdloan_reserve` redirect unreserved balance to the para's current sibling sovereign account when the `depositor` is a known `para`-prefixed sovereign account and a translation record exists, instead of crediting the stale address.

### Proof of Concept
Integration test outline (extending `pallets/ah-ops/src/tests.rs`):
1. Set up `RcLeaseReserve::insert((block, para_id, para_sov_child(para_id)), amount)` and reserve `amount` on `para_sov_child(para_id)`.
2. Call `translate_para_sovereign_child_to_sibling_derived(root, para_id, path, para_sov_child(para_id), para_sov_sibling(para_id))` — assert free/reducible balance moves to the sibling account, but note reserved `amount` stays on `para_sov_child`.
3. Advance block past `block`.
4. As an arbitrary signed account (not the para), call `unreserve_lease_deposit(signed, block, Some(para_sov_child(para_id)), para_id)`.
5. Assert: `RcLeaseReserve` entry removed, `amount` now free balance on `para_sov_child(para_id)` (the old, unrecognized account), and NOT on `para_sov_sibling(para_id)`.
6. Assert that no further mechanism exists in the pallet to move that balance to the sibling account, demonstrating permanent stranding — i.e., a follow-up call to `translate_para_sovereign_child_to_sibling_derived` for the same accounts would need to be manually re-triggered by governance, which is not enforced anywhere in the extrinsic logic.

### Citations

**File:** pallets/ah-ops/src/lib.rs (L137-150)
```rust
	/// Amount of balance that was reserved for winning a lease auction.
	///
	/// `unreserve_lease_deposit` can be permissionlessly called once the block number passed to
	/// unreserve the deposit. It is implicitly called by `withdraw_crowdloan_contribution`.
	///  
	/// The account here can either be a crowdloan account or a solo bidder. If it is a crowdloan
	/// account, then the summed up contributions for it in the contributions map will equate the
	/// reserved balance here.
	///
	/// The keys are as follows:
	/// - Block number after which the deposit can be unreserved.
	/// - The para_id of the lease slot.
	/// - The account that will have the balance unreserved.
	/// - The balance to be unreserved.
```

**File:** pallets/ah-ops/src/lib.rs (L289-301)
```rust
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

**File:** pallets/ah-ops/src/lib.rs (L332-344)
```rust
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
```

**File:** pallets/ah-ops/src/lib.rs (L415-435)
```rust
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

**File:** pallets/ah-ops/src/lib.rs (L562-662)
```rust
		/// Actual logic of `translate_para_sovereign_child_to_sibling_derived`.
		pub fn do_translate_para_sovereign_child_to_sibling_derived(
			para_id: u16,
			derivation_path: Vec<u16>,
			from: T::AccountId,
			to: T::AccountId,
		) -> Result<(), Error<T>> {
			if derivation_path.len() > 10 {
				return Err(Error::<T>::TooLongDerivationPath);
			}

			let para_child = Self::para_sov_child(para_id);
			let para_sibling = Self::para_sov_sibling(para_id);
			let para_child_derived = derivative_account_id_recursive(para_child, &derivation_path);
			let para_sibling_derived =
				derivative_account_id_recursive(para_sibling, &derivation_path);

			ensure!(para_child_derived == from, Error::<T>::WrongDerivedTranslation);
			ensure!(para_sibling_derived == to, Error::<T>::WrongDerivedTranslation);

			if frame_system::Account::<T>::get(&from) == Default::default() {
				// Nothing to do if the account does not exist
				return Ok(());
			}
			pallet_balances::Pallet::<T>::ensure_upgraded(&from); // prevent future headache

			// Get the bonded amount that we will force-unstake.
			let active_bonded =
				pallet_staking_async::Ledger::<T>::get(&from).map(|l| l.active).unwrap_or(0);
			let total_bonded =
				pallet_staking_async::Ledger::<T>::get(&from).map(|l| l.total).unwrap_or(0);

			if total_bonded > 0 {
				// Force unstake. The actual function is private, so we use the call:
				pallet_staking_async::Pallet::<T>::force_unstake(
					frame_system::Origin::<T>::Root.into(),
					from.clone(),
					0, // does not matter
				)
				.map_err(|_| Error::<T>::FailedToForceUnstake)?;
			}

			// First, create the new account by transferring ED.
			let reducible_dot = <<T as Config>::Currency as FungibleInspect<_>>::reducible_balance(
				&from,
				Preservation::Preserve,
				Fortitude::Polite,
			);
			let ed = <<T as Config>::Currency as FungibleInspect<_>>::minimum_balance();
			if reducible_dot >= ed {
				<<T as Config>::Currency as FungibleMutate<_>>::transfer(
					&from,
					&to,
					ed,
					Preservation::Expendable,
				)
				.defensive()
				.map_err(|_| Error::<T>::FailedToTransfer)?;
			}

			// Transfer all assets to the new account. This must not create or reap an account since
			// that could fail, depending on whether all assets are sufficient.
			for id in T::RelevantAssets::get() {
				let amount = <T as Config>::Fungibles::reducible_balance(
					id.clone(),
					&from,
					Preservation::Expendable,
					Fortitude::Force,
				);

				if amount.is_zero() {
					continue;
				}

				<<T as Config>::Fungibles as FungiblesMutate<_>>::transfer(
					id.clone(),
					&from,
					&to,
					amount,
					Preservation::Expendable,
				)
				.defensive()
				.map_err(|_| Error::<T>::FailedToTransfer)?;
			}

			// Now transfer the remaining DOT to the new account.
			let remaining_dot = <<T as Config>::Currency as FungibleInspect<_>>::reducible_balance(
				&from,
				Preservation::Expendable,
				Fortitude::Force,
			);
			if remaining_dot > 0 {
				<<T as Config>::Currency as FungibleMutate<_>>::transfer(
					&from,
					&to,
					remaining_dot,
					Preservation::Expendable,
				)
				.defensive()
				.map_err(|_| Error::<T>::FailedToTransfer)?;
			}
```
