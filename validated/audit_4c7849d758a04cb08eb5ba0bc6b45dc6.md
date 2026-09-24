No vulnerability found for this question.

The Compound-fork report describes exchange-rate slippage: a user's `redeem`/`mint` amount depends on `exchangeRateStoredInternal()`, which can shift between transaction submission and execution because another party's mint/redeem changes `totalCash`/`totalBorrows`/`totalSupply`, and there is no deadline/slippage check.

The closest FRAME analog is `pallet-nomination-pools`, where `points_to_balance` / `balance_to_point` implement an equivalent share-ratio conversion for `join`/`bond_extra`/`unbond` [1](#0-0) . Just like Compound's exchange rate, this points-to-balance ratio is influenced by pool state (slashing, rewards) and can shift between when a member submits `join`/`unbond` and when it executes [2](#0-1) .

However, this is documented, intended design rather than a violated invariant: the pallet's own docs explicitly describe that "the ratio of point to balance is different and might not be 1... as time goes on, for reasons such as slashing, the ratio gets broken," and instruct wallets to always display the current point/balance ratio to users rather than assume 1:1 [2](#0-1) . There is no privileged/attacker action here that extracts value from another user — any shift in the ratio comes from legitimate pool activity (rewards, slashes) affecting all members proportionally, not from an attacker manipulating state to profit at a victim's expense. This matches the scan's exclusion criteria for "pure front-running/economic attacks" and slippage-type issues without a demonstrable theft or integrity break, so it does not qualify as a reportable analog under the given constraints.

### Citations

**File:** substrate/frame/nomination-pools/src/lib.rs (L196-203)
```rust
//! * Points and balance are not the same! Any pool member, at any point in time, can have points in
//!   either the bonded pool or any of the unbonding pools. The crucial fact is that in any of these
//!   pools, the ratio of point to balance is different and might not be 1. Each pool starts with a
//!   ratio of 1, but as time goes on, for reasons such as slashing, the ratio gets broken. Over
//!   time, 100 points in a bonded pool can be worth 90 DOTs. Make sure you are either representing
//!   points as points (not as DOTs), or even better, always display both: “You have x points in
//!   pool y which is worth z DOTs”. See here and here for examples of how to calculate point to
//!   balance ratio of each pool (it is almost trivial ;))
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3475-3522)
```rust
	fn balance_to_point(
		current_balance: BalanceOf<T>,
		current_points: BalanceOf<T>,
		new_funds: BalanceOf<T>,
	) -> BalanceOf<T> {
		let u256 = T::BalanceToU256::convert;
		let balance = T::U256ToBalance::convert;
		match (current_balance.is_zero(), current_points.is_zero()) {
			(_, true) => new_funds.saturating_mul(POINTS_TO_BALANCE_INIT_RATIO.into()),
			(true, false) => {
				// The pool was totally slashed.
				// This is the equivalent of `(current_points / 1) * new_funds`.
				new_funds.saturating_mul(current_points)
			},
			(false, false) => {
				// Equivalent to (current_points / current_balance) * new_funds
				balance(
					u256(current_points)
						.saturating_mul(u256(new_funds))
						// We check for zero above
						.div(u256(current_balance)),
				)
			},
		}
	}

	/// Calculate the equivalent balance of `points` in a pool with `current_balance` and
	/// `current_points`.
	fn point_to_balance(
		current_balance: BalanceOf<T>,
		current_points: BalanceOf<T>,
		points: BalanceOf<T>,
	) -> BalanceOf<T> {
		let u256 = T::BalanceToU256::convert;
		let balance = T::U256ToBalance::convert;
		if current_balance.is_zero() || current_points.is_zero() || points.is_zero() {
			// There is nothing to unbond
			return Zero::zero();
		}

		// Equivalent of (current_balance / current_points) * points
		balance(
			u256(current_balance)
				.saturating_mul(u256(points))
				// We check for zero above
				.div(u256(current_points)),
		)
	}
```
