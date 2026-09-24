This confirms the analog doesn't hold. The pool's `balance_to_point` / `points_to_balance` ratio is computed from `T::StakeAdapter::active_stake(...)`, which reads from `pallet_staking`'s `StakingLedger.active` field, not from the pool account's raw free balance.No vulnerability found for this question.

**Analysis rationale:**

The report describes the classic ERC4626 "first depositor" share-inflation attack: an attacker mints a negligible number of shares, then donates raw underlying tokens directly to the vault contract to inflate `totalAssets` without minting shares, corrupting the `assets/shares` ratio for subsequent depositors.

I looked for the closest FRAME analog — `pallet-nomination-pools`, which has an almost identical points↔balance ratio mechanism [1](#0-0) . However, the critical difference that breaks the analogy is where the "asset balance" side of the ratio comes from:

- In `balance_to_point`/`points_to_balance`, the pool's balance side of the ratio is `T::StakeAdapter::active_stake(...)`, not the pool account's raw free/token balance [2](#0-1) .
- `active_stake` reads the `active` field of the `StakingLedger` maintained by `pallet-staking`/`pallet-staking-async`, which is only mutated through `bond`/`bond_extra`/`unbond` calls [3](#0-2) [4](#0-3) .
- Points are always issued in `try_bond_funds`/`issue` at the exact moment new funds are bonded into that ledger, before the stake mutation happens, so the points:balance ratio cannot be desynchronized by an out-of-band "donation" [5](#0-4) .

Consequently there is no way for an attacker to increase the pool's `active_stake` (the denominator/numerator used for the ratio) without going through `join`/`bond_extra`, which always issues proportional points simultaneously — there is no "direct transfer to the vault" equivalent that bypasses share issuance the way sending DAI directly to the sGLP/vault address does in the ERC4626 report. Additionally, pool creation requires `amount >= Pallet::<T>::depositor_min_bond()` [6](#0-5) , which is tied to `minimum_nominator_bond` and is not a negligible "1 wei" style deposit, further undermining the "cheap first depositor" precondition from the report.

No other user-facing share/ratio-based entry point (assets, balances-transaction-payment, asset-conversion) showed an equivalent "externally donate raw balance to inflate a first-mover's ratio" pattern reachable by an unprivileged signed extrinsic in the scoped code. I found no demonstrable Polkadot SDK analog for this bug class.

### Citations

**File:** substrate/frame/nomination-pools/src/lib.rs (L240-256)
```rust
//! When the pool already has some balance, we want the value of a point before the transfer to
//! equal the value of a point after the transfer. So, when a member joins a bonded pool with a
//! given `amount_transferred`, we maintain the ratio of bonded balance to points such that:
//!
//! ```text
//! balance_after_transfer / points_after_transfer == balance_before_transfer / points_before_transfer;
//! ```
//!
//! To achieve this, we issue points based on the following:
//!
//! ```text
//! points_issued = (points_before_transfer / balance_before_transfer) * amount_transferred;
//! ```
//!
//! For new bonded pools we can set the points issued per balance arbitrarily. In this
//! implementation we use a 1 points to 1 balance ratio for pool creation (see
//! [`POINTS_TO_BALANCE_INIT_RATIO`]).
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L1064-1078)
```rust
	/// Convert the given amount of balance to points given the current pool state.
	///
	/// This is often used for bonding and issuing new funds into the pool.
	fn balance_to_point(&self, new_funds: BalanceOf<T>) -> BalanceOf<T> {
		let bonded_balance = T::StakeAdapter::active_stake(Pool::from(self.bonded_account()));
		Pallet::<T>::balance_to_point(bonded_balance, self.points, new_funds)
	}

	/// Convert the given number of points to balance given the current pool state.
	///
	/// This is often used for unbonding.
	fn points_to_balance(&self, points: BalanceOf<T>) -> BalanceOf<T> {
		let bonded_balance = T::StakeAdapter::active_stake(Pool::from(self.bonded_account()));
		Pallet::<T>::point_to_balance(bonded_balance, self.points, points)
	}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L1308-1336)
```rust
	/// Bond exactly `amount` from `who`'s funds into this pool. Increases the [`TotalValueLocked`]
	/// by `amount`.
	///
	/// If the bond is [`BondType::Create`], [`Staking::bond`] is called, and `who` is allowed to be
	/// killed. Otherwise, [`Staking::bond_extra`] is called and `who` cannot be killed.
	///
	/// Returns `Ok(points_issues)`, `Err` otherwise.
	fn try_bond_funds(
		&mut self,
		who: &T::AccountId,
		amount: BalanceOf<T>,
		ty: BondType,
	) -> Result<BalanceOf<T>, DispatchError> {
		// We must calculate the points issued *before* we bond who's funds, else points:balance
		// ratio will be wrong.
		let points_issued = self.issue(amount);

		T::StakeAdapter::pledge_bond(
			Member::from(who.clone()),
			Pool::from(self.bonded_account()),
			&self.reward_account(),
			amount,
			ty,
		)?;
		TotalValueLocked::<T>::mutate(|tvl| {
			tvl.saturating_accrue(amount);
		});

		Ok(points_issued)
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3588-3588)
```rust
		ensure!(amount >= Pallet::<T>::depositor_min_bond(), Error::<T>::MinimumBondNotMet);
```

**File:** substrate/frame/nomination-pools/src/adapter.rs (L128-131)
```rust
	/// See [`StakingInterface::active_stake`].
	fn active_stake(pool_account: Pool<Self::AccountId>) -> Self::Balance {
		Self::CoreStaking::active_stake(&pool_account.0).unwrap_or_default()
	}
```

**File:** substrate/frame/staking/src/lib.rs (L496-512)
```rust
	/// The stash account whose balance is actually locked and at stake.
	pub stash: T::AccountId,

	/// The total amount of the stash's balance that we are currently accounting for.
	/// It's just `active` plus all the `unlocking` balances.
	#[codec(compact)]
	pub total: BalanceOf<T>,

	/// The total amount of the stash's balance that will be at stake in any forthcoming
	/// rounds.
	#[codec(compact)]
	pub active: BalanceOf<T>,

	/// Any balance that is becoming free, which may eventually be transferred out of the stash
	/// (assuming it doesn't get slashed first). It is assumed that this will be treated as a first
	/// in, first out queue where the new (higher value) eras get pushed on the back.
	pub unlocking: BoundedVec<UnlockChunk<BalanceOf<T>>, T::MaxUnlockingChunks>,
```
