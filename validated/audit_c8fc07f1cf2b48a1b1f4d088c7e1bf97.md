### Title
`pallet-elections-phragmen::vote` rejects a voter whose stake equals exactly `Currency::minimum_balance()` due to strict `>` check - ([File: substrate/frame/elections-phragmen/src/lib.rs])

### Summary
The `vote` extrinsic in `pallet-elections-phragmen` enforces `ensure!(value > T::Currency::minimum_balance(), Error::<T>::LowBalance);` [1](#0-0)  This is the same class of off-by-one boundary bug flagged in the external FrankenDAO report (`proposalThreshold` comparison using `>` instead of `>=`): an account whose vote stake is *exactly equal* to the minimum balance is unconditionally rejected, even though intuitively the minimum balance should be an acceptable lower bound.

### Finding Description
`Pallet::vote` is a real, publicly reachable signed extrinsic [2](#0-1)  callable by any signed account with no privileged role required. Inside it, after validating vote count and target-count bounds, the pallet checks the caller-supplied `value` parameter against `T::Currency::minimum_balance()`:

```rust
ensure!(value > T::Currency::minimum_balance(), Error::<T>::LowBalance);
``` [1](#0-0) 

If `value == minimum_balance()` exactly, the extrinsic returns `Error::LowBalance` and the vote is rejected, even though such a value should logically be sufficient to satisfy a "minimum" bound. This mirrors the reported invariant violation in the FrankenDAO report where `votes > proposalThreshold` incorrectly excluded the boundary case `votes == proposalThreshold`.

### Impact Explanation
This is a functional/usability edge-case bug, not a theft, unauthorized-dispatch, or fund-loss vulnerability. An account holding a balance exactly equal to `minimum_balance()` cannot cast a vote in council elections via this pallet, and must either increase their balance above minimum or reduce it (technically to below ED, risking reaping) to work around the restriction. There is no loss of funds, no bypass of access control, and no chain-halting condition. Per the classification guidance this would sit, at most, at Low severity — a strict boundary/off-by-one denial of a legitimate low-value voter, not a Critical/High-impact security bug.

### Likelihood Explanation
Likelihood of the exact-equality condition occurring naturally is low but non-zero — any account that deliberately or coincidentally holds exactly `ExistentialDeposit` (which frequently equals `minimum_balance()`) and tries to vote with their full balance will hit this. It requires no attacker privilege and is trivially reachable by any signed account, but the practical exploitation value is negligible since the impact is a mere reverted transaction (with fee cost), not a security compromise.

### Recommendation
Change the comparison to `>=` (or explicitly document/allow `value == minimum_balance()` as valid), i.e.:
```rust
ensure!(value >= T::Currency::minimum_balance(), Error::<T>::LowBalance);
```
This aligns the check with the general convention in Substrate/FRAME of treating "minimum" thresholds as inclusive lower bounds (as done elsewhere, e.g. `ensure!(value >= T::MinimumDeposit::get(), ...)` in `pallet-democracy`'s `propose` [3](#0-2) , which correctly uses `>=`).

### Proof of Concept
No executable PoC was run against a live test harness in this investigation (no filesystem/terminal access available in this ask-only session). The finding is based on static code inspection:
- Failed guard: `ensure!(value > T::Currency::minimum_balance(), Error::<T>::LowBalance)` at `substrate/frame/elections-phragmen/src/lib.rs:396`.
- A minimal reproduction would be: in `substrate/frame/elections-phragmen/src/tests.rs`, call `Elections::vote(RuntimeOrigin::signed(<account>), vec![<candidate>], T::Currency::minimum_balance())` for an account whose stake equals exactly `minimum_balance()`, and observe `Error::<Test>::LowBalance` returned instead of `Ok(())`. This was not executed in this session; it is a proposed reproduction path only.

Overall assessment: this is a legitimate structural analog of the reported bug class (strict `>` vs `>=` on a "minimum/threshold" comparison) reachable via a real unprivileged signed extrinsic, but its impact is confined to a Low-severity usability/DoS-on-a-single-vote edge case rather than a fund-loss or governance-bypass vulnerability, and I could not confirm whether `pallet-elections-phragmen` is currently wired into any live Parity-maintained bounty-eligible production runtime (it does not appear in the Polkadot/Kusama/Westend/AssetHub production runtimes in this repo, only in `substrate/bin/node/runtime` (kitchensink, a test/dev runtime) and `polkadot/runtime/rococo` (a testnet)), which is relevant to bounty-eligibility per the scan's requirement to verify a live program and affected version.

### Citations

**File:** substrate/frame/elections-phragmen/src/lib.rs (L371-376)
```rust
		pub fn vote(
			origin: OriginFor<T>,
			votes: Vec<T::AccountId>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;
```

**File:** substrate/frame/elections-phragmen/src/lib.rs (L396-396)
```rust
			ensure!(value > T::Currency::minimum_balance(), Error::<T>::LowBalance);
```

**File:** substrate/frame/democracy/src/lib.rs (L591-592)
```rust
			let who = T::SubmitOrigin::ensure_origin(origin)?;
			ensure!(value >= T::MinimumDeposit::get(), Error::<T>::ValueLow);
```
