A closer FRAME analog to the ETHPoolLPFactory griefing bug exists in the crowdloan pallet, where `do_contribute` performs a raised-vs-cap check that mirrors the vault's `maxStakingAmountPerValidator` check.

### Title
Crowdloan can be griefed to permanently cap the fund below `cap` once the remaining headroom is smaller than `MinContribution` - (File: `polkadot/runtime/common/src/crowdloan/mod.rs`)

### Summary
`Pallet::do_contribute` enforces `value >= MinContribution` and, separately, `fund.raised + value <= fund.cap`. An unprivileged contributor can strategically size a contribution so that `cap - raised` becomes smaller than `MinContribution`, permanently blocking every subsequent `contribute` call for the rest of the crowdloan's life, because any legal contribution (which must be `>= MinContribution`) will always push `raised` past `cap`.

### Finding Description
`do_contribute` first requires `value >= T::MinContribution::get()`, then computes the new `raised` total and requires it not exceed the immutable `cap` set at fund creation: [1](#0-0) 

`cap` is fixed at `create` time and cannot be changed afterward: [2](#0-1) 

Because `fund.raised` is only persisted at the very end of the function via `Funds::<T>::insert`, a failing `CapExceeded` check reverts the whole extrinsic (no funds move, `raised` unchanged in storage) — exactly analogous to `_depositETHForStaking` reverting on `maxStakingAmountPerValidator`: [3](#0-2) [4](#0-3) 

`contribute` is a plain signed extrinsic reachable by anyone, with no privileged role required: [5](#0-4) 

Root cause: the "remaining headroom to `cap`" is not checked against `MinContribution` before accepting a contribution amount that leaves a dust-sized remainder. Once `cap - raised < MinContribution`, no contribution — by definition `>= MinContribution` — can ever be accepted again, because it would trip `CapExceeded`. This is structurally identical to the reported bug: a griefer deposits an amount that leaves the "remaining-to-target" gap below the protocol's own minimum unit, permanently blocking further deposits.

### Impact Explanation
An attacker (any signed account, no special permission) can grief a competing project's crowdloan by contributing an amount calculated to leave `cap - raised` just under `MinContribution`. From that point on:
- No further contributions can be accepted for the remainder of the crowdloan period (`contribute` always reverts with `CapExceeded`).
- The crowdloan is permanently prevented from reaching its intended `cap`, potentially costing the project the difference in raised funds and, in an auction context, potentially the auction itself if the shortfall matters relative to competitors.

This is a real griefing/DoS vector on a public financial mechanism, but the harm is bounded: existing contributions are unaffected and remain refundable; only the *unused headroom* near `cap` is permanently wasted. This differs from the original report's impact (vault deposits becoming completely stuck/unusable for staking), so the severity here is best characterized as Low/Medium rather than the accepted Medium in the original report.

### Likelihood Explanation
High feasibility: the attacker only needs to submit one well-sized `contribute` transaction near the fund's `cap`, paying only the contributed amount itself (which is refundable to them like any other contributor) and normal transaction fees. No collusion, governance, or privileged access is required. The only constraint is being able to observe `fund.raised` and `fund.cap` (both public storage) and act before others close the gap — a race that favors whoever transacts first/last to hit the residual gap.

### Recommendation
In `do_contribute`, when `fund.cap - fund.raised < T::MinContribution::get()` but is still non-zero, either:
- allow a "top-up to cap" contribution smaller than `MinContribution` when it exactly closes the remaining gap to `cap`, or
- reject contributions whose *resulting* raised total would leave a remaining gap smaller than `MinContribution` (rounding the accepted amount to consume the whole cap in one shot), so the fund can always still reach exactly `cap`.

### Proof of Concept
Not executed against a live network; reasoning is based on static code inspection of `do_contribute` (`polkadot/runtime/common/src/crowdloan/mod.rs:749-831`) and its call-site guards. A minimal integration reproduction would use the existing `crowdloan` pallet mock/test harness (`polkadot/runtime/common/src/crowdloan/mod.rs` test module, e.g. `contribute_handles_basic_errors`) extended as follows:
1. `create` a fund with `cap = C`.
2. Contributor A calls `contribute` with `value = C - MinContribution + 1` (succeeds, `raised = C - MinContribution + 1`).
3. Contributor B calls `contribute` with `value = MinContribution` (or any legal value) — must fail with `Error::<T>::CapExceeded` in `ensure!(fund.raised <= fund.cap, Error::<T>::CapExceeded)` at `polkadot/runtime/common/src/crowdloan/mod.rs:759`, proving the fund is now permanently unable to reach `cap` for the remainder of the campaign.

This flow was not run in this session; a background agent with repository access should add and run the above test in the pallet's existing mock harness to confirm the `CapExceeded` revert and record the exact failed-guard evidence.

### Citations

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L369-376)
```rust
		pub fn create(
			origin: OriginFor<T>,
			#[pallet::compact] index: ParaId,
			#[pallet::compact] cap: BalanceOf<T>,
			#[pallet::compact] first_period: LeasePeriodOf<T>,
			#[pallet::compact] last_period: LeasePeriodOf<T>,
			#[pallet::compact] end: BlockNumberFor<T>,
			verifier: Option<MultiSigner>,
```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L444-454)
```rust
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::contribute())]
		pub fn contribute(
			origin: OriginFor<T>,
			#[pallet::compact] index: ParaId,
			#[pallet::compact] value: BalanceOf<T>,
			signature: Option<MultiSignature>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::do_contribute(who, index, value, signature, KeepAlive)
		}
```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L756-759)
```rust
		ensure!(value >= T::MinContribution::get(), Error::<T>::ContributionTooSmall);
		let mut fund = Funds::<T>::get(index).ok_or(Error::<T>::InvalidParaId)?;
		fund.raised = fund.raised.checked_add(&value).ok_or(Error::<T>::Overflow)?;
		ensure!(fund.raised <= fund.cap, Error::<T>::CapExceeded);
```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L793-797)
```rust
		CurrencyOf::<T>::transfer(&who, &fund_account, value, existence)?;
		CurrencyOf::<T>::deactivate(value);

		let balance = old_balance.saturating_add(value);
		Self::contribution_put(fund.fund_index, &who, &balance, &memo);
```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L827-827)
```rust
		Funds::<T>::insert(index, &fund);
```
