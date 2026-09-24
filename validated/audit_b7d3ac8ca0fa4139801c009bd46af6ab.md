No vulnerability found for this question.

The reported issue is that `cleanToken()`/`cleanETH()` in the DODO contracts are gated by `onlyOwner`, and the concern raised is that if the owner's private key is stolen, funds could be drained. This is explicitly an owner/privileged-key-compromise scenario, which the scan prompt's attacker model excludes ("The attacker has no privileged role, governance control or stolen keys ... no malicious peer/node/validator/collator/relayer, controlled parachain, forged inherent or dishonest external chain is ever allowed").

Searching the polkadot-sdk codebase for structurally analogous "admin sweeps funds" patterns turns up only intentionally privileged extrinsics such as `pallet_balances::force_transfer` (root-only) [1](#0-0) , `pallet_assets::force_transfer` (admin-only) [2](#0-1) , `pallet_broker::force_transfer` (Root/AdminOrigin) [3](#0-2) , and `pallet_indices::force_transfer` (Root) [4](#0-3) . All of these are, by design, gated behind `ensure_root` or an equivalent privileged origin check, and their "risk" is identical in nature to the reported issue: compromise of the privileged key/origin. There is also a genuinely permissionless sweep, `pallet_bounties::reclaim_bounty_funds`, but it is scoped narrowly to closed bounty accounts with no live owner, not an arbitrary admin-controlled sweep of user funds, so it isn't analogous to the reported unsafe pattern [5](#0-4) .

None of these represent a case where an unprivileged, un-permissioned caller can trigger the fund-draining behavior — the reachable entry point always requires the same privileged origin whose compromise is exactly what the report worries about, and that threat model is out of scope for this analysis. No FRAME/XCM analog with a genuine unprivileged attacker entry point was found.

### Citations

**File:** substrate/frame/balances/src/lib.rs (L660-674)
```rust
		/// Exactly as `transfer_allow_death`, except the origin must be root and the source account
		/// may be specified.
		#[pallet::call_index(2)]
		pub fn force_transfer(
			origin: OriginFor<T>,
			source: AccountIdLookupOf<T>,
			dest: AccountIdLookupOf<T>,
			#[pallet::compact] value: T::Balance,
		) -> DispatchResult {
			ensure_root(origin)?;
			let source = T::Lookup::lookup(source)?;
			let dest = T::Lookup::lookup(dest)?;
			<Self as fungible::Mutate<_>>::transfer(&source, &dest, value, Expendable)?;
			Ok(())
		}
```

**File:** substrate/frame/assets/src/lib.rs (L99-112)
```rust
//! ### Permissioned Functions
//!
//! * `force_create`: Creates a new asset class without taking any deposit.
//! * `force_set_metadata`: Set the metadata of an asset class.
//! * `force_clear_metadata`: Remove the metadata of an asset class.
//! * `force_asset_status`: Alter an asset class's attributes.
//! * `force_cancel_approval`: Rescind a previous approval.
//!
//! ### Privileged Functions
//!
//! * `destroy`: Destroys an entire asset class; called by the asset class's Owner.
//! * `mint`: Increases the asset balance of an account; called by the asset class's Issuer.
//! * `burn`: Decreases the asset balance of an account; called by the asset class's Admin.
//! * `force_transfer`: Transfers between arbitrary accounts; called by the asset class's Admin.
```

**File:** substrate/frame/broker/src/lib.rs (L1071-1087)
```rust
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

**File:** substrate/frame/indices/src/lib.rs (L177-195)
```rust
		/// The dispatch origin for this call must be _Root_.
		///
		/// - `index`: the index to be (re-)assigned.
		/// - `new`: the new owner of the index. This function is a no-op if it is equal to sender.
		/// - `freeze`: if set to `true`, will freeze the index so it cannot be transferred.
		///
		/// Emits `IndexAssigned` if successful.
		///
		/// ## Complexity
		/// - `O(1)`.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::force_transfer())]
		pub fn force_transfer(
			origin: OriginFor<T>,
			new: AccountIdLookupOf<T>,
			index: T::AccountIndex,
			freeze: bool,
		) -> DispatchResult {
			ensure_root(origin)?;
```

**File:** substrate/frame/bounties/src/lib.rs (L1058-1090)
```rust
		#[pallet::call_index(11)]
		#[pallet::weight(<T as Config<I>>::WeightInfo::reclaim_bounty_funds())]
		pub fn reclaim_bounty_funds(
			origin: OriginFor<T>,
			#[pallet::compact] bounty_id: BountyIndex,
		) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;

			// A live bounty still manages its account, so leave it untouched.
			ensure!(!Bounties::<T, I>::contains_key(bounty_id), Error::<T, I>::BountyStillActive);

			debug_assert!(
				T::ChildBountyManager::child_bounties_count(bounty_id) == 0,
				"child bounties should not exist for a closed bounty"
			);

			let bounty_account = Self::bounty_account_id(bounty_id);
			let treasury_account = Self::account_id();

			let transferred = T::TransferAllAssets::force_transfer_all_assets(
				&bounty_account,
				&treasury_account,
			)?;

			// Free only if something moved, otherwise paid to prevent griefing.
			if !transferred {
				return Ok(Pays::Yes.into());
			}

			Self::deposit_event(Event::<T, I>::BountyFundsReclaimed { bounty_id });

			Ok(Pays::No.into())
		}
```
