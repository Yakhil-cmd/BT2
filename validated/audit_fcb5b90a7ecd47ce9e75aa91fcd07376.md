### Title
Nomination-pools `create_with_pool_id` lets anyone squat a dissolved pool's `PoolId`, hijacking stale `join`/`nominate`/`bond_extra` calls that reference the ID without binding to the pool's identity - (File: `substrate/frame/nomination-pools/src/lib.rs`)

### Summary
The Royco `RecipeKernel` bug is a class of "unbound reference-by-ID" vulnerability: users commit to an action against a state object identified only by a mutable, reusable numeric ID (`targetMarketID`), and that ID can later be re-associated with a completely different, attacker-controlled object, so the user's later-executed action is silently redirected. The Polkadot SDK analog exists in `pallet-nomination-pools`: pools are identified purely by a `PoolId: u32` counter (`LastPoolId`), and the permissionless extrinsic `create_with_pool_id` lets **any** signed account re-create a pool at a previously-used (now-dissolved) `PoolId`, with entirely new roles (`root`/`nominator`/`bouncer`). Every subsequent call that references a pool only by `pool_id` (`join`, `bond_extra`, `nominate`, `set_metadata`, `set_state`, etc.) has no cryptographic binding to the pool's original configuration/creator, so a stale or delayed transaction referencing that `pool_id` will execute against the attacker's substituted pool.

### Finding Description
`Pools::create` allocates a fresh `pool_id` from the ever-incrementing `LastPoolId` counter: [1](#0-0) 

When the last member (the depositor) leaves via `withdraw_unbonded`, `dissolve_pool` fully removes the pool's storage, including the `BondedPools` entry that keyed the ID, while leaving `LastPoolId` unchanged: [2](#0-1) 

This frees the numeric `pool_id` for reuse while it remains `< LastPoolId`. `create_with_pool_id` explicitly allows re-creating a pool at that exact freed ID, gated only by `ensure_signed` (any account) and the two checks that the ID is not currently in use and is below `LastPoolId` — there is no requirement that the caller be the original depositor or have any relation to the previous pool: [3](#0-2) 

`Self::do_create` then installs entirely new `roles` (root/nominator/bouncer are supplied by the new caller) under the reused `pool_id`: [4](#0-3) 

Every user-facing call that operates on a pool takes only the bare `pool_id: PoolId`, never a hash or commitment to the pool's identity/roles at the time the user formed their intent — e.g. `join(amount, pool_id)` (referenced in tests at `substrate/frame/nomination-pools/src/tests.rs` lines 812-882), `nominate(origin, pool_id, validators)`, and `set_metadata(origin, pool_id, metadata)`: [5](#0-4) [6](#0-5) 

This mirrors the report's root cause exactly: a permissionless "create" indexed by a reusable/incrementing ID, referenced elsewhere purely by that ID with no hash/identity check, allowing an attacker to inject a different, malicious instance under the same reference once the original instance's slot becomes eligible for reuse.

### Impact Explanation
A victim who signs a `join(amount, pool_id)` extrinsic (offline signing, wallet queue, mortal extrinsic not yet included, or a transaction that gets displaced by a fork/re-org and is later re-included) is depositing funds based on the pool's reputation/config at signing time. If, before that extrinsic lands, the pool at `pool_id` is fully dissolved (a legitimate, permissionless event when the last member exits) and an attacker calls `create_with_pool_id` to recreate a pool at the same `pool_id` with attacker-controlled `root`/`nominator`/`bouncer`, the victim's transaction executes against the attacker's pool instead. The attacker as `root` can then set `commission` to redirect staking rewards, or as `bouncer`/`root` place the pool in `Blocked` state to trap the victim's bonded funds, or as `nominator` direct stake to validators of the attacker's choosing. This is a fund-theft/fund-freezing vector reachable by any ordinary signed account with no privileged role, matching the report's "steal funds via ID reuse" pattern.

### Likelihood Explanation
Exploitability depends on a race: the attacker must observe a pool's dissolution and win the race to call `create_with_pool_id` for that exact `pool_id` before the stale `join`/`nominate`/`set_metadata` transaction targeting it is included — a narrow but not implausible window given public dissolve events and permissionless resubmission of pending calls, especially around short-lived fork/re-org windows before finality. No governance, validator collusion, or stolen keys are required, only ordinary signed transactions, satisfying the "no privileged role" constraint. Likelihood is Medium: it requires timing/race conditions and a victim with a not-yet-executed, ID-only reference, but the missing binding is a structural gap present in the pallet's public API today.

### Recommendation
Do not allow permissionless reuse of a previously-used `PoolId` by an unrelated account. Either remove `create_with_pool_id` from being callable by arbitrary signed origins (restrict to the original depositor, or require `ForceOrigin`), or bind pool references used in `join`/`nominate`/`bond_extra`/`set_metadata`/etc. to a commitment (e.g., a hash of the pool's roles/creation block) captured at intent-signing time so re-creation under the same numeric ID cannot silently redirect a user's action, analogous to the Royco fix that replaced `targetMarketID` lookups with a market-hash check.

### Proof of Concept
Not executed against a live network. Reproduction sketch for a local FRAME test harness (`substrate/frame/nomination-pools/src/tests.rs`), not run in this session:
1. Depositor `10` creates pool 1 via `Pools::create` (existing test helper `ExtBuilder::default()`).
2. Member `10` fully unbonds and calls `Pools::withdraw_unbonded(10, 10, 0)`, causing `dissolve_pool` to remove `BondedPools::<Runtime>::get(1)` while `LastPoolId` remains ≥ 1 (matches existing assertions in `withdraw_unbonded_kill` benchmark, lines 596-605 showing `BondedPools` entry removed post-dissolve).
3. Attacker account `999` calls `Pools::create_with_pool_id(amount, root=999, nominator=999, bouncer=999, pool_id=1)`, which succeeds because `!BondedPools::contains_key(1)` and `1 < LastPoolId`.
4. A victim's previously-signed `Pools::join(amount, 1)` extrinsic, submitted before step 2/3 completed, executes afterward and deposits into the attacker-controlled pool 1.
Expected state: the victim's funds should only ever reach the pool they intended (bound to the original creator/roles); actual state: funds land in a pool with attacker-controlled `root`/`nominator`/`bouncer`. This flow was traced through source but not executed as a running test in this session — a background engineering task would be required to add and run this integration test to confirm the exact runtime error surface (e.g., whether `MinJoinBond`/`OpenPool` checks incidentally block the exact race window).

### Citations

**File:** substrate/frame/nomination-pools/src/lib.rs (L2586-2595)
```rust
		) -> DispatchResult {
			let depositor = ensure_signed(origin)?;

			let pool_id = LastPoolId::<T>::try_mutate::<_, Error<T>, _>(|id| {
				*id = id.checked_add(1).ok_or(Error::<T>::OverflowRisk)?;
				Ok(*id)
			})?;

			Self::do_create(depositor, amount, root, nominator, bouncer, pool_id)
		}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L2603-2619)
```rust
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::create())]
		pub fn create_with_pool_id(
			origin: OriginFor<T>,
			#[pallet::compact] amount: BalanceOf<T>,
			root: AccountIdLookupOf<T>,
			nominator: AccountIdLookupOf<T>,
			bouncer: AccountIdLookupOf<T>,
			pool_id: PoolId,
		) -> DispatchResult {
			let depositor = ensure_signed(origin)?;

			ensure!(!BondedPools::<T>::contains_key(pool_id), Error::<T>::PoolIdInUse);
			ensure!(pool_id < LastPoolId::<T>::get(), Error::<T>::InvalidPoolId);

			Self::do_create(depositor, amount, root, nominator, bouncer, pool_id)
		}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L2635-2658)
```rust
		pub fn nominate(
			origin: OriginFor<T>,
			pool_id: PoolId,
			validators: Vec<T::AccountId>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let bonded_pool = BondedPool::<T>::get(pool_id).ok_or(Error::<T>::PoolNotFound)?;
			// ensure pool is not in an un-migrated state.
			ensure!(!Self::api_pool_needs_delegate_migration(pool_id), Error::<T>::NotMigrated);
			ensure!(bonded_pool.can_nominate(&who), Error::<T>::NotNominator);

			let depositor_points = PoolMembers::<T>::get(&bonded_pool.roles.depositor)
				.ok_or(Error::<T>::PoolMemberNotFound)?
				.active_points();

			ensure!(
				bonded_pool.points_to_balance(depositor_points) >= Self::depositor_min_bond(),
				Error::<T>::MinimumBondNotMet
			);

			T::StakeAdapter::nominate(Pool::from(bonded_pool.bonded_account()), validators).map(
				|_| Self::deposit_event(Event::<T>::PoolNominationMade { pool_id, caller: who }),
			)
		}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L2703-2725)
```rust
		pub fn set_metadata(
			origin: OriginFor<T>,
			pool_id: PoolId,
			metadata: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let metadata: BoundedVec<_, _> =
				metadata.try_into().map_err(|_| Error::<T>::MetadataExceedsMaxLen)?;
			ensure!(
				BondedPool::<T>::get(pool_id)
					.ok_or(Error::<T>::PoolNotFound)?
					.can_set_metadata(&who),
				Error::<T>::DoesNotHavePermission
			);
			// ensure pool is not in an un-migrated state.
			ensure!(!Self::api_pool_needs_delegate_migration(pool_id), Error::<T>::NotMigrated);

			Metadata::<T>::mutate(pool_id, |pool_meta| *pool_meta = metadata);

			Self::deposit_event(Event::<T>::MetadataUpdated { pool_id, caller: who });

			Ok(())
		}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3358-3422)
```rust
	/// Remove everything related to the given bonded pool.
	///
	/// Metadata and all of the sub-pools are also deleted. All accounts are dusted and the leftover
	/// of the reward account is returned to the depositor.
	pub fn dissolve_pool(bonded_pool: BondedPool<T>) {
		let reward_account = bonded_pool.reward_account();
		let bonded_account = bonded_pool.bonded_account();

		ReversePoolIdLookup::<T>::remove(&bonded_account);
		RewardPools::<T>::remove(bonded_pool.id);
		SubPoolsStorage::<T>::remove(bonded_pool.id);

		// remove the ED restriction from the pool reward account.
		let _ = Self::unfreeze_pool_deposit(&bonded_pool.reward_account()).defensive();

		// Kill accounts from storage by making their balance go below ED. We assume that the
		// accounts have no references that would prevent destruction once we get to this point. We
		// don't work with the system pallet directly, but
		// 1. we drain the reward account and kill it. This account should never have any extra
		// consumers anyway.
		// 2. the bonded account should become a 'killed stash' in the staking system, and all of
		//    its consumers removed.
		defensive_assert!(
			frame_system::Pallet::<T>::consumers(&reward_account) == 0,
			"reward account of dissolving pool should have no consumers"
		);
		defensive_assert!(
			frame_system::Pallet::<T>::consumers(&bonded_account) == 0,
			"bonded account of dissolving pool should have no consumers"
		);
		defensive_assert!(
			T::StakeAdapter::total_stake(Pool::from(bonded_pool.bonded_account())) == Zero::zero(),
			"dissolving pool should not have any stake in the staking pallet"
		);

		// This shouldn't fail, but if it does we don't really care. Remaining balance can consist
		// of unclaimed pending commission, erroneous transfers to the reward account, etc.
		let reward_pool_remaining = T::Currency::reducible_balance(
			&reward_account,
			Preservation::Expendable,
			Fortitude::Polite,
		);
		let _ = T::Currency::transfer(
			&reward_account,
			&bonded_pool.roles.depositor,
			reward_pool_remaining,
			Preservation::Expendable,
		);

		defensive_assert!(
			T::Currency::total_balance(&reward_account) == Zero::zero(),
			"could not transfer all amount to depositor while dissolving pool"
		);
		// NOTE: Defensively force set balance to zero.
		T::Currency::set_balance(&reward_account, Zero::zero());

		// dissolve pool account.
		let _ = T::StakeAdapter::dissolve(Pool::from(bonded_account)).defensive();

		Self::deposit_event(Event::<T>::Destroyed { pool_id: bonded_pool.id });
		// Remove bonded pool metadata.
		Metadata::<T>::remove(bonded_pool.id);

		bonded_pool.remove();
	}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3573-3627)
```rust
	fn do_create(
		who: T::AccountId,
		amount: BalanceOf<T>,
		root: AccountIdLookupOf<T>,
		nominator: AccountIdLookupOf<T>,
		bouncer: AccountIdLookupOf<T>,
		pool_id: PoolId,
	) -> DispatchResult {
		// ensure depositor is not restricted from joining the pool.
		ensure!(!T::Filter::contains(&who), Error::<T>::Restricted);

		let root = T::Lookup::lookup(root)?;
		let nominator = T::Lookup::lookup(nominator)?;
		let bouncer = T::Lookup::lookup(bouncer)?;

		ensure!(amount >= Pallet::<T>::depositor_min_bond(), Error::<T>::MinimumBondNotMet);
		ensure!(
			MaxPools::<T>::get().map_or(true, |max_pools| BondedPools::<T>::count() < max_pools),
			Error::<T>::MaxPools
		);
		ensure!(!PoolMembers::<T>::contains_key(&who), Error::<T>::AccountBelongsToOtherPool);
		let mut bonded_pool = BondedPool::<T>::new(
			pool_id,
			PoolRoles {
				root: Some(root),
				nominator: Some(nominator),
				bouncer: Some(bouncer),
				depositor: who.clone(),
			},
		);

		bonded_pool.try_inc_members()?;
		let points = bonded_pool.try_bond_funds(&who, amount, BondType::Create)?;

		// Transfer the minimum balance for the reward account.
		T::Currency::transfer(
			&who,
			&bonded_pool.reward_account(),
			T::Currency::minimum_balance(),
			Preservation::Expendable,
		)?;

		// Restrict reward account balance from going below ED.
		Self::freeze_pool_deposit(&bonded_pool.reward_account())?;

		PoolMembers::<T>::insert(
			who.clone(),
			PoolMember::<T> {
				pool_id,
				points,
				last_recorded_reward_counter: Zero::zero(),
				unbonding_eras: Default::default(),
			},
		);
		RewardPools::<T>::insert(
```
