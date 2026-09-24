No vulnerability found for this question.

**Rationale:** The Kintsu report describes an external smart-contract wrapper that loops over multiple `nomination-pools` "agents" and reverts entirely if any one pool is in `Blocked`/`Destroying` state — a DoS specific to Kintsu's own aggregation logic, not to the underlying pallet.

In `polkadot-sdk`'s `pallet-nomination-pools`, both entry points behave exactly as documented and intended:

- `join` explicitly requires `PoolState::Open` via `ok_to_join`, which calls `ensure!(self.state == PoolState::Open, Error::<T>::NotOpen)` before allowing a new member to bond into the pool. [1](#0-0) [2](#0-1) 

- `do_bond_extra` (used by both `bond_extra` and `bond_extra_other`) calls `bonded_pool.ok_to_be_open()` which rejects the operation with `CanNotChangeState`/`OverflowRisk` if the pool is destroying or otherwise unhealthy. [3](#0-2) [4](#0-3) 

These reverts are the pallet's intended access-control invariant — the module documentation explicitly states "No members can join" a `Blocked` or `Destroying` pool. [5](#0-4) 

Tests confirm this is expected, deterministic behavior rather than an unguarded fault: joining a `Blocked` or `Destroying` pool correctly and cleanly returns `Error::NotOpen`. [6](#0-5) 

There is no unbounded loop, no cross-pool aggregation, and no attacker-controlled input that forces this check to be bypassed or to cause state corruption within `pallet-nomination-pools` itself — the "revert" is a single, well-formed `DispatchError` for a single pool operation, matching the documented single-pool membership model (`AccountBelongsToOtherPool` enforces one pool per account). Since Kintsu's vulnerability arises purely from application-level orchestration logic that iterates across several pools and is not present in polkadot-sdk's runtime pallet code, there is no demonstrable FRAME-level analog with a real user entry point, missing check, or measurable loss/integrity break.

### Citations

**File:** substrate/frame/nomination-pools/src/lib.rs (L117-125)
```rust
//! To help facilitate pool administration the pool has one of three states (see [`PoolState`]):
//!
//! * Open: Anyone can join the pool and no members can be permissionlessly removed.
//! * Blocked: No members can join and some admin roles can kick members. Kicking is not instant,
//!   and follows the same process of `unbond` and then `withdraw_unbonded`. In other words,
//!   administrators can permissionlessly unbond other members.
//! * Destroying: No members can join and all members can be permissionlessly removed with
//!   [`Call::unbond`] and [`Call::withdraw_unbonded`]. Once a pool is in destroying state, it
//!   cannot be reverted to another state.
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L1181-1215)
```rust
	/// Whether or not the pool is ok to be in `PoolSate::Open`. If this returns an `Err`, then the
	/// pool is unrecoverable and should be in the destroying state.
	fn ok_to_be_open(&self) -> Result<(), DispatchError> {
		ensure!(!self.is_destroying(), Error::<T>::CanNotChangeState);

		let bonded_balance = T::StakeAdapter::active_stake(Pool::from(self.bonded_account()));
		ensure!(!bonded_balance.is_zero(), Error::<T>::OverflowRisk);

		let points_to_balance_ratio_floor = self
			.points
			// We checked for zero above
			.div(bonded_balance);

		let max_points_to_balance = T::MaxPointsToBalance::get();

		// Pool points can inflate relative to balance, but only if the pool is slashed.
		// If we cap the ratio of points:balance so one cannot join a pool that has been slashed
		// by `max_points_to_balance`%, if not zero.
		ensure!(
			points_to_balance_ratio_floor < max_points_to_balance.into(),
			Error::<T>::OverflowRisk
		);

		// then we can be decently confident the bonding pool points will not overflow
		// `BalanceOf<T>`. Note that these are just heuristics.

		Ok(())
	}

	/// Check that the pool can accept a member with `new_funds`.
	fn ok_to_join(&self) -> Result<(), DispatchError> {
		ensure!(self.state == PoolState::Open, Error::<T>::NotOpen);
		self.ok_to_be_open()?;
		Ok(())
	}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L2126-2137)
```rust
			// ensure pool is not in an un-migrated state.
			ensure!(!Self::api_pool_needs_delegate_migration(pool_id), Error::<T>::NotMigrated);

			// ensure account is not restricted from joining the pool.
			ensure!(!T::Filter::contains(&who), Error::<T>::Restricted);

			ensure!(amount >= MinJoinBond::<T>::get(), Error::<T>::MinimumBondNotMet);
			// If a member already exists that means they already belong to a pool
			ensure!(!PoolMembers::<T>::contains_key(&who), Error::<T>::AccountBelongsToOtherPool);

			let mut bonded_pool = BondedPool::<T>::get(pool_id).ok_or(Error::<T>::PoolNotFound)?;
			bonded_pool.ok_to_join()?;
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3685-3696)
```rust
		let (points_issued, bonded) = match extra {
			BondExtra::FreeBalance(amount) => {
				(bonded_pool.try_bond_funds(&member_account, amount, BondType::Extra)?, amount)
			},
			BondExtra::Rewards => {
				(bonded_pool.try_bond_funds(&member_account, claimed, BondType::Extra)?, claimed)
			},
		};

		bonded_pool.ok_to_be_open()?;
		member.points =
			member.points.checked_add(&points_issued).ok_or(Error::<T>::OverflowRisk)?;
```

**File:** substrate/frame/nomination-pools/src/tests.rs (L934-945)
```rust
			// Cannot join a pool that isn't open
			unsafe_set_state(123, PoolState::Blocked);
			assert_noop!(
				Pools::join(RuntimeOrigin::signed(11), max_points_to_balance, 123),
				Error::<Runtime>::NotOpen
			);

			unsafe_set_state(123, PoolState::Destroying);
			assert_noop!(
				Pools::join(RuntimeOrigin::signed(11), max_points_to_balance, 123),
				Error::<Runtime>::NotOpen
			);
```
