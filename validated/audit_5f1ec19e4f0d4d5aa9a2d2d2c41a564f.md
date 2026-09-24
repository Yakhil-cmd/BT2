### Title
Permissionless `stake()` in `pallet-asset-rewards` lets any account block `cleanup_pool` indefinitely, permanently locking pool admin's storage deposit and reward funds - ([File: substrate/frame/asset-rewards/src/lib.rs])

### Summary
`pallet-asset-rewards::cleanup_pool` refuses to run while any `PoolStakers` entry exists for the pool, checked via `PoolStakers::<T>::iter_key_prefix(pool_id).next()`, mirroring the reported Solana bug's strict "balance must be exactly zero" gate on account closure [1](#0-0) . Because `stake()` is a permissionless, signed, non-privileged extrinsic open to any account with a nonzero balance of the staked asset, an attacker can grief the pool admin by staking a trivial, non-refundable-by-admin amount and simply never unstaking, permanently denying `cleanup_pool` [2](#0-1) .

### Finding Description
`cleanup_pool` is the only mechanism available to the pool `admin` to reclaim the pool's `Consideration` storage deposit (`PoolCost`) and sweep back unused reward tokens; it hard-fails with `Error::NonEmptyPool` unless there are zero `PoolStakers` entries for the pool:

```rust
let stakers = PoolStakers::<T>::iter_key_prefix(pool_id).next();
ensure!(stakers.is_none(), Error::<T>::NonEmptyPool);
``` [3](#0-2) 

`stake(origin, pool_id, amount)` is callable by any `ensure_signed` origin — there is no admin check, no minimum-stake requirement beyond what the freeze mechanism enforces, and no cooldown/lock preventing the staker from choosing to never call `unstake`:

```rust
pub fn stake(origin: OriginFor<T>, pool_id: PoolId, amount: T::Balance) -> DispatchResult {
    let staker = ensure_signed(origin)?;
    ...
    T::AssetsFreezer::increase_frozen(...)?;
    ...
    PoolStakers::<T>::insert(pool_id, &staker, staker_info);
    ...
}
``` [4](#0-3) 

`unstake` is only callable by the staker themselves while the pool is not yet expired (`ensure!(now > pool_info.expiry_block || caller == staker, BadOrigin)`), meaning the admin has **no way to force-remove** a griefing staker's entry before pool expiry, and after expiry the staker still has no obligation to unstake:

```rust
ensure!(now > pool_info.expiry_block || caller == staker, BadOrigin);
``` [5](#0-4) 

This is the FRAME analog of the reported bug's invariant violation: a strict "state must be exactly empty" precondition on a privileged cleanup/closure action, where the emptiness condition is attacker-writable via a normal, permissionless user-facing entry point (`stake`, analogous to the direct token transfer to `window_base_token_account`). Unlike `pallet-balances`/`pallet-assets`, which handle exactly this class of griefing via existential-deposit dusting and automatic reaping/`DustRemoval`, `pallet-asset-rewards` has no dusting, sweeping, or force-unstake mechanism for the admin — the check is purely `is_none()` with no tolerance and no sweep instruction, exactly matching the report's root cause and its recommended fix pattern (remove the strict check or add a sweep instruction).

The pallet's own test suite acknowledges and exercises exactly this scenario without providing the admin any bypass:
```rust
// stake to prevent pool cleanup
assert_ok!(StakingRewards::stake(RuntimeOrigin::signed(staker), pool_id, 100));
assert_noop!(
    StakingRewards::cleanup_pool(RuntimeOrigin::signed(admin), pool_id),
    Error::<MockRuntime>::NonEmptyPool
);
``` [6](#0-5) 

### Impact Explanation
A malicious, unprivileged account can permanently prevent the pool `admin` from ever calling `cleanup_pool`:
- The admin's storage `Consideration`/`HoldReason::PoolCreation` deposit (held via `T::Consideration`, e.g. `HoldConsideration`) can never be released back to the depositor, because `PoolCost::<T>::take(pool_id)` and `Consideration::drop` are only reached after the `NonEmptyPool` check passes [7](#0-6) .
- Reward tokens still sitting in the pool's pot account (`pool_info.account`) can never be swept back to the admin, since that transfer is likewise gated behind the same check [8](#0-7) .
- The `Pools` and `PoolCost` storage entries become permanently un-removable, causing indefinite storage bloat for that pool and blocking pool-id reuse/lifecycle management.

This is a deterministic, irreversible denial-of-service on a legitimate pallet action (cleanup/fund-recovery), triggerable at negligible cost (stake amount can be minimal, bounded only by asset's minimum balance/ED considerations and tx fee), by any ordinary user with no special privileges — consistent with a Medium severity finding (denial of service / fund lock, not theft or unbacked issuance).

### Likelihood Explanation
High likelihood of triggerability: `stake` requires only a signed origin and possession of a small amount of the pool's staked asset; no governance, no validator/collator/relayer collusion, and no privileged role are needed. The attacker's only "cost" is the staked amount itself, which remains frozen but recoverable to the attacker at will (they can even unstake it after achieving the DoS, then restake trivially to keep blocking cleanup, or simply never unstake). The scenario is already reproduced in the pallet's own unit test (`success_only_when_pool_empty`), confirming the check is reachable through the real extrinsic path with no additional preconditions.

### Recommendation
Apply the same fix pattern the external report's vendor used: either (a) remove the strict `NonEmptyPool` check and instead force-unstake/return remaining staked+reward balances during `cleanup_pool`, or (b) add a dedicated `admin`-only instruction that can force-unstake residual/dust staker positions (e.g., below some minimal threshold or after expiry) so `cleanup_pool` can proceed. At minimum, allow the admin to force-unstake stragglers after `expiry_block` has passed, since `unstake` already special-cases post-expiry logic (`now > pool_info.expiry_block`) but currently only for the staker/caller path, not for admin-initiated forced removal.

### Proof of Concept
Guard hit: `ensure!(stakers.is_none(), Error::<T>::NonEmptyPool)` at `substrate/frame/asset-rewards/src/lib.rs:704`.

Reproduction is directly demonstrated by the pallet's existing mock-runtime unit test `cleanup_pool::success_only_when_pool_empty` [9](#0-8) , which:
1. Creates a pool as `admin` (privileged `CreatePoolOrigin`, not attacker-controlled).
2. Has an arbitrary signed account `staker` (id `20`, non-privileged) call `stake(pool_id, 100)` — a fully permissionless call.
3. Confirms `cleanup_pool` called by `admin` fails with `Error::NonEmptyPool` while any nonzero stake remains, even after partial unstake to 50.
4. Only succeeds once the staker voluntarily fully unstakes — something the admin cannot compel.

This confirms the failed guard is reachable via the genuine extrinsic path with an unprivileged signer and no forged/mocked authority, matching the report's bug class (strict emptiness check blockable by an attacker-controlled deposit, with no sweep/force path for the account owner/admin). I did not execute this against a live network; the test above is an existing, unmodified harness test in the repository demonstrating the exact failure condition, not a new PoC I ran.

### Citations

**File:** substrate/frame/asset-rewards/src/lib.rs (L469-502)
```rust
		/// Stake additional tokens in a pool.
		///
		/// A freeze is placed on the staked tokens.
		#[pallet::call_index(1)]
		pub fn stake(origin: OriginFor<T>, pool_id: PoolId, amount: T::Balance) -> DispatchResult {
			let staker = ensure_signed(origin)?;

			// Always start by updating staker and pool rewards.
			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			let staker_info = PoolStakers::<T>::get(pool_id, &staker).unwrap_or_default();
			let (mut pool_info, mut staker_info) =
				Self::update_pool_and_staker_rewards(&pool_info, &staker_info)?;

			T::AssetsFreezer::increase_frozen(
				pool_info.staked_asset_id.clone(),
				&FreezeReason::Staked.into(),
				&staker,
				amount,
			)?;

			// Update Pools.
			pool_info.total_tokens_staked.ensure_add_assign(amount)?;

			Pools::<T>::insert(pool_id, pool_info);

			// Update PoolStakers.
			staker_info.amount.ensure_add_assign(amount)?;
			PoolStakers::<T>::insert(pool_id, &staker, staker_info);

			// Emit event.
			Self::deposit_event(Event::Staked { staker, pool_id, amount });

			Ok(())
		}
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L524-526)
```rust
			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			let now = T::BlockNumberProvider::current_block_number();
			ensure!(now > pool_info.expiry_block || caller == staker, BadOrigin);
```

**File:** substrate/frame/asset-rewards/src/lib.rs (L696-729)
```rust
		#[pallet::call_index(8)]
		pub fn cleanup_pool(origin: OriginFor<T>, pool_id: PoolId) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let pool_info = Pools::<T>::get(pool_id).ok_or(Error::<T>::NonExistentPool)?;
			ensure!(pool_info.admin == who, BadOrigin);

			let stakers = PoolStakers::<T>::iter_key_prefix(pool_id).next();
			ensure!(stakers.is_none(), Error::<T>::NonEmptyPool);

			let pool_balance = T::Assets::reducible_balance(
				pool_info.reward_asset_id.clone(),
				&pool_info.account,
				Preservation::Expendable,
				Fortitude::Polite,
			);
			T::Assets::transfer(
				pool_info.reward_asset_id,
				&pool_info.account,
				&pool_info.admin,
				pool_balance,
				Preservation::Expendable,
			)?;

			if let Some((who, cost)) = PoolCost::<T>::take(pool_id) {
				T::Consideration::drop(cost, &who)?;
			}

			Pools::<T>::remove(pool_id);

			Self::deposit_event(Event::PoolCleanedUp { pool_id });

			Ok(())
		}
```

**File:** substrate/frame/asset-rewards/src/tests.rs (L1233-1267)
```rust
	#[test]
	fn success_only_when_pool_empty() {
		new_test_ext().execute_with(|| {
			let pool_id = 0;
			let staker = 20;
			let admin = DEFAULT_ADMIN;

			create_default_pool();

			// stake to prevent pool cleanup
			assert_ok!(StakingRewards::stake(RuntimeOrigin::signed(staker), pool_id, 100));

			assert_noop!(
				StakingRewards::cleanup_pool(RuntimeOrigin::signed(admin), pool_id),
				Error::<MockRuntime>::NonEmptyPool
			);

			// unstake partially
			assert_ok!(StakingRewards::unstake(RuntimeOrigin::signed(staker), pool_id, 50, None));

			assert_noop!(
				StakingRewards::cleanup_pool(RuntimeOrigin::signed(admin), pool_id),
				Error::<MockRuntime>::NonEmptyPool
			);

			// unstake all
			assert_ok!(StakingRewards::unstake(RuntimeOrigin::signed(staker), pool_id, 50, None));

			assert_ok!(StakingRewards::cleanup_pool(RuntimeOrigin::signed(admin), pool_id),);

			assert_eq!(Pools::<MockRuntime>::get(pool_id), None);
			assert_eq!(PoolStakers::<MockRuntime>::iter_prefix_values(pool_id).count(), 0);
			assert_eq!(PoolCost::<MockRuntime>::get(pool_id), None);
		});
	}
```
