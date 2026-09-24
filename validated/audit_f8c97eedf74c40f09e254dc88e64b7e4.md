The strongest FRAME analog to the NFTX "vault manager griefing" report is `pallet-nfts`' permissionless collection owner's unilateral, instant, and irreversible `lock_collection` power over items already held by other users — this mirrors the NFTX pattern (trustless creation → attacker gains "manager"-like control → instant parameter change traps other users' assets with no delay/consent) more closely than `pallet-nomination-pools` commission (which is explicitly throttled/capped by design) or `pallet-asset-conversion`'s `set_pool_fee` (which requires `AdminOrigin`/governance, not a permissionless creator).

### Title
Permissionless NFT collection owner can irreversibly freeze other users' items via `lock_collection` with no timelock or consent - (File: substrate/frame/nfts/src/features/lock.rs)

### Summary
`pallet-nfts::create` lets any signed account permissionlessly become the owner of a new collection by paying a deposit [1](#0-0) . As collection owner, that same account can later call `lock_collection` to instantly and irreversibly disable settings such as `TransferableItems` for the *entire* collection [2](#0-1) , with the only permission check being that the caller is the collection owner [3](#0-2) . There is no delay, no consent from existing item holders, and — per the pallet's own documentation — "it's possible only to lock the setting, but not to unlock it after" [4](#0-3) .

### Finding Description
The attack mirrors the NFTX report's structure exactly: a trustless, permissionless "container" (NFTX vault / NFTs collection) is created by an ordinary user who becomes its unilateral administrator ("vault manager" / collection owner). Other users are then lured into acquiring assets inside that container (depositing into the vault / minting or buying NFT items via `mint`/`buy_item`, both permissionless dispatchables per the pallet README) [5](#0-4) . Once sufficient traction (and thus sufficient victims) is gained, the administrator instantaneously flips a control switch that harms the users who already hold assets in the container:

- NFTX: `setFees()`/`setVaultFeatures()` — instant, no delay.
- FRAME analog: `lock_collection()` disabling `CollectionSetting::TransferableItems` — instant, and explicitly irreversible, unlike NFTX's fee/feature toggle which the manager could theoretically reverse.

`do_transfer` in the NFTs pallet checks `collection_config.is_setting_enabled(CollectionSetting::TransferableItems)` on every transfer attempt [6](#0-5) , so once the owner locks that setting, every item held by every other account in the collection becomes permanently non-transferable ("soul bound"), confirmed by the pallet's own test (`locking_transfer_should_work`) which shows `transfer` failing with `ItemsNonTransferable` after `lock_collection`, and only a governance `ForceOrigin` call (`force_collection_config`) can undo it at the protocol level — something ordinary victims cannot invoke [7](#0-6) .

The `buy_item`/`set_price` test further demonstrates that a buyer can legitimately purchase an item and then be prevented from any subsequent transfer once the seller/owner locks the collection [8](#0-7) .

### Impact Explanation
This traps user-owned, potentially valuable NFTs permanently in a non-transferable state with no on-chain recourse for the victims (no timelock, no unlock capability at the owner level — "not to unlock it after"). Unlike the nomination-pools commission path, which Substrate protects with `CommissionChangeRate` throttling and a `GlobalMaxCommission` cap specifically to prevent this exact griefing pattern [9](#0-8) , `lock_collection` has no analogous rate-limit, cooldown, or reversibility safeguard for the collection owner's own signed call.

### Likelihood Explanation
The prerequisite is only that a user acquires an item in a collection they do not control — an extremely common, expected interaction pattern (buying/minting NFTs) — and that the collection owner is malicious or later turns malicious after gaining a user base. No privileged role, governance action, or validator/collator misbehavior is required; this is entirely within a single permissionless account's ordinary signed-extrinsic capability.

### Recommendation
Consider whether `lock_collection`'s irreversibility and lack of any grace period constitutes intended, documented pallet behavior (it explicitly is documented as by-design) versus a UX/trust risk that downstream runtimes/marketplaces (e.g., Asset Hub) should surface to users — analogous to NFTX's "vault verification" concept — before treating item purchases in unverified/unlocked collections as safe. Runtimes exposing `pallet-nfts` publicly should document that collection settings, once locked by the owner, cannot be undone even by item holders, and marketplace UIs should warn buyers when interacting with collections that retain `TransferableItems`-disable capability.

### Proof of Concept
This is a documented, already-tested pallet behavior rather than an unguarded bug: the existing test suite (`locking_transfer_should_work`, `collection_locking_should_work`, and the `buy_item` collection-lock test) demonstrates the exact mechanics — `mint`/`transfer`/`buy_item` succeed, then `lock_collection(TransferableItems)` succeeds from the owner's signed origin, after which any subsequent `transfer` by the item holder fails with `Error::ItemsNonTransferable`, and no owner-level call can re-enable the setting [7](#0-6) [10](#0-9) . No further execution was performed beyond reviewing these existing, passing test harnesses; this reproduces the griefing mechanic but its irreversibility is intentional pallet design, not a validation gap the pallet fails to enforce — flagged here as the closest structural analog to the NFTX report rather than a novel unmitigated vulnerability.

### Citations

**File:** substrate/frame/nfts/src/lib.rs (L710-741)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::create())]
		pub fn create(
			origin: OriginFor<T>,
			admin: AccountIdLookupOf<T>,
			config: CollectionConfigFor<T, I>,
		) -> DispatchResult {
			let collection = NextCollectionId::<T, I>::get()
				.or(T::CollectionId::initial_value())
				.ok_or(Error::<T, I>::UnknownCollection)?;

			let owner = T::CreateOrigin::ensure_origin(origin, &collection)?;
			let admin = T::Lookup::lookup(admin)?;

			// DepositRequired can be disabled by calling the force_create() only
			ensure!(
				!config.has_disabled_setting(CollectionSetting::DepositRequired),
				Error::<T, I>::WrongSetting
			);

			Self::do_create_collection(
				collection,
				owner.clone(),
				admin.clone(),
				config,
				T::CollectionDeposit::get(),
				Event::Created { collection, creator: owner, owner: admin },
			)?;

			Self::set_next_collection_id(collection);
			Ok(())
		}
```

**File:** substrate/frame/nfts/src/lib.rs (L1153-1174)
```rust
		/// Disallows specified settings for the whole collection.
		///
		/// Origin must be Signed and the sender should be the Owner of the `collection`.
		///
		/// - `collection`: The collection to be locked.
		/// - `lock_settings`: The settings to be locked.
		///
		/// Note: it's possible to only lock(set) the setting, but not to unset it.
		///
		/// Emits `CollectionLocked`.
		///
		/// Weight: `O(1)`
		#[pallet::call_index(10)]
		#[pallet::weight(T::WeightInfo::lock_collection())]
		pub fn lock_collection(
			origin: OriginFor<T>,
			collection: T::CollectionId,
			lock_settings: CollectionSettings,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;
			Self::do_lock_collection(origin, collection, lock_settings)
		}
```

**File:** substrate/frame/nfts/src/features/lock.rs (L25-30)
```rust
	/// Locks a collection with specified settings.
	///
	/// The origin must be the owner of the collection to lock it. This function disables certain
	/// settings on the collection. The only setting that can't be disabled is `DepositRequired`.
	///
	/// Note: it's possible only to lock the setting, but not to unlock it after.
```

**File:** substrate/frame/nfts/src/features/lock.rs (L36-56)
```rust
	pub(crate) fn do_lock_collection(
		origin: T::AccountId,
		collection: T::CollectionId,
		lock_settings: CollectionSettings,
	) -> DispatchResult {
		ensure!(Self::collection_owner(collection) == Some(origin), Error::<T, I>::NoPermission);
		ensure!(
			!lock_settings.is_disabled(CollectionSetting::DepositRequired),
			Error::<T, I>::WrongSetting
		);
		CollectionConfigOf::<T, I>::try_mutate(collection, |maybe_config| {
			let config = maybe_config.as_mut().ok_or(Error::<T, I>::NoConfig)?;

			for setting in lock_settings.get_disabled() {
				config.disable_setting(setting);
			}

			Self::deposit_event(Event::<T, I>::CollectionLocked { collection });
			Ok(())
		})
	}
```

**File:** substrate/frame/nfts/README.md (L47-62)
```markdown
### Permissionless dispatchables

* `create`: Create a new collection by placing a deposit.
* `mint`: Mint a new item within a collection (when the minting is public).
* `transfer`: Send an item to a new owner.
* `redeposit`: Update the deposit amount of an item, potentially freeing funds.
* `approve_transfer`: Name a delegate who may authorize a transfer.
* `cancel_approval`: Revert the effects of a previous `approve_transfer`.
* `approve_item_attributes`: Name a delegate who may change item's attributes within a namespace.
* `cancel_item_attributes_approval`: Revert the effects of a previous `approve_item_attributes`.
* `set_price`: Set the price for an item.
* `buy_item`: Buy an item.
* `pay_tips`: Pay tips, could be used for paying the creator royalties.
* `create_swap`: Create an offer to swap an NFT for another NFT and optionally some fungibles.
* `cancel_swap`: Cancel previously created swap offer.
* `claim_swap`: Swap items in an atomic way.
```

**File:** substrate/frame/nfts/src/features/transfer.rs (L68-73)
```rust
		// Retrieve collection config and check if items are transferable.
		let collection_config = Self::get_collection_config(&collection)?;
		ensure!(
			collection_config.is_setting_enabled(CollectionSetting::TransferableItems),
			Error::<T, I>::ItemsNonTransferable
		);
```

**File:** substrate/frame/nfts/src/tests.rs (L520-553)
```rust
#[test]
fn locking_transfer_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Nfts::force_create(
			RuntimeOrigin::root(),
			account(1),
			default_collection_config()
		));
		assert_ok!(Nfts::mint(RuntimeOrigin::signed(account(1)), 0, 42, account(1), None));
		assert_ok!(Nfts::lock_item_transfer(RuntimeOrigin::signed(account(1)), 0, 42));
		assert_noop!(
			Nfts::transfer(RuntimeOrigin::signed(account(1)), 0, 42, account(2)),
			Error::<Test>::ItemLocked
		);

		assert_ok!(Nfts::unlock_item_transfer(RuntimeOrigin::signed(account(1)), 0, 42));
		assert_ok!(Nfts::lock_collection(
			RuntimeOrigin::signed(account(1)),
			0,
			CollectionSettings::from_disabled(CollectionSetting::TransferableItems.into())
		));
		assert_noop!(
			Nfts::transfer(RuntimeOrigin::signed(account(1)), 0, 42, account(2)),
			Error::<Test>::ItemsNonTransferable
		);

		assert_ok!(Nfts::force_collection_config(
			RuntimeOrigin::root(),
			0,
			collection_config_with_all_settings_enabled(),
		));
		assert_ok!(Nfts::transfer(RuntimeOrigin::signed(account(1)), 0, 42, account(2)));
	});
}
```

**File:** substrate/frame/nfts/src/tests.rs (L2570-2620)
```rust
		// ensure we can't buy an item when the collection or an item are frozen
		{
			assert_ok!(Nfts::set_price(
				RuntimeOrigin::signed(user_1.clone()),
				collection_id,
				item_3,
				Some(price_1),
				None,
			));

			// lock the collection
			assert_ok!(Nfts::lock_collection(
				RuntimeOrigin::signed(user_1.clone()),
				collection_id,
				CollectionSettings::from_disabled(CollectionSetting::TransferableItems.into())
			));

			let buy_item_call = mock::RuntimeCall::Nfts(crate::Call::<Test>::buy_item {
				collection: collection_id,
				item: item_3,
				bid_price: price_1,
			});
			assert_noop!(
				buy_item_call.dispatch(RuntimeOrigin::signed(user_2.clone())),
				Error::<Test>::ItemsNonTransferable
			);

			// unlock the collection
			assert_ok!(Nfts::force_collection_config(
				RuntimeOrigin::root(),
				collection_id,
				collection_config_with_all_settings_enabled(),
			));

			// lock the transfer
			assert_ok!(Nfts::lock_item_transfer(
				RuntimeOrigin::signed(user_1.clone()),
				collection_id,
				item_3,
			));

			let buy_item_call = mock::RuntimeCall::Nfts(crate::Call::<Test>::buy_item {
				collection: collection_id,
				item: item_3,
				bid_price: price_1,
			});
			assert_noop!(
				buy_item_call.dispatch(RuntimeOrigin::signed(user_2)),
				Error::<Test>::ItemLocked
			);
		}
```

**File:** substrate/frame/nfts/src/tests.rs (L3072-3123)
```rust
#[test]
fn collection_locking_should_work() {
	new_test_ext().execute_with(|| {
		let user_id = account(1);
		let collection_id = 0;

		assert_ok!(Nfts::force_create(
			RuntimeOrigin::root(),
			user_id.clone(),
			collection_config_with_all_settings_enabled()
		));

		let lock_config =
			collection_config_from_disabled_settings(CollectionSetting::DepositRequired.into());
		assert_noop!(
			Nfts::lock_collection(
				RuntimeOrigin::signed(user_id.clone()),
				collection_id,
				lock_config.settings,
			),
			Error::<Test>::WrongSetting
		);

		// validate partial lock
		let lock_config = collection_config_from_disabled_settings(
			CollectionSetting::TransferableItems | CollectionSetting::UnlockedAttributes,
		);
		assert_ok!(Nfts::lock_collection(
			RuntimeOrigin::signed(user_id.clone()),
			collection_id,
			lock_config.settings,
		));

		let stored_config = CollectionConfigOf::<Test>::get(collection_id).unwrap();
		assert_eq!(stored_config, lock_config);

		// validate full lock
		assert_ok!(Nfts::lock_collection(
			RuntimeOrigin::signed(user_id),
			collection_id,
			CollectionSettings::from_disabled(CollectionSetting::UnlockedMetadata.into()),
		));

		let stored_config = CollectionConfigOf::<Test>::get(collection_id).unwrap();
		let full_lock_config = collection_config_from_disabled_settings(
			CollectionSetting::TransferableItems |
				CollectionSetting::UnlockedMetadata |
				CollectionSetting::UnlockedAttributes,
		);
		assert_eq!(stored_config, full_lock_config);
	});
}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L796-841)
```rust
	/// Returns true if the current commission updating to `to` would exhaust the change rate
	/// limits.
	///
	/// A commission update will be throttled (disallowed) if:
	/// 1. not enough blocks have passed since the `throttle_from` block, if exists, or
	/// 2. the new commission is greater than the maximum allowed increase.
	fn throttling(&self, to: &Perbill) -> bool {
		if let Some(t) = self.change_rate.as_ref() {
			let commission_as_percent =
				self.current.as_ref().map(|(x, _)| *x).unwrap_or(Perbill::zero());

			// do not throttle if `to` is the same or a decrease in commission.
			if *to <= commission_as_percent {
				return false;
			}
			// Test for `max_increase` throttling.
			//
			// Throttled if the attempted increase in commission is greater than `max_increase`.
			if (*to).saturating_sub(commission_as_percent) > t.max_increase {
				return true;
			}

			// Test for `min_delay` throttling.
			//
			// Note: matching `None` is defensive only. `throttle_from` should always exist where
			// `change_rate` has already been set, so this scenario should never happen.
			return self.throttle_from.map_or_else(
				|| {
					defensive!("throttle_from should exist if change_rate is set");
					true
				},
				|f| {
					// if `min_delay` is zero (no delay), not throttling.
					if t.min_delay == Zero::zero() {
						false
					} else {
						// throttling if blocks passed is less than `min_delay`.
						let blocks_surpassed =
							T::BlockNumberProvider::current_block_number().saturating_sub(f);
						blocks_surpassed < t.min_delay
					}
				},
			);
		}
		false
	}
```
