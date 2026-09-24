### Title
Crowdloan `refund()` batch refund is atomically bricked by a single reaped/dust contributor account - (File: `polkadot/runtime/common/src/crowdloan/mod.rs`)

### Summary
`pallet_crowdloan::refund()` (and `withdraw()`) refund contributors by calling `CurrencyOf::<T>::transfer(&fund_account, &who, balance, AllowDeath)?` inside a loop over multiple contributors in a single dispatchable [1](#0-0) . Because FRAME dispatchables are atomic (a returned `Err` rolls back all storage mutations made during that call, including `contribution_kill` and `fund.raised` updates already applied to earlier contributors in the same loop iteration), a single contributor whose refund transfer fails aborts the refund for every other contributor processed in that call, and — since the child-trie iteration order is deterministic — blocks all subsequent `refund()` calls from making any progress past that entry. This mirrors the reported Axis Finance issue where one "poisoned" participant (blacklisted bidder) breaks batch settlement for every other participant.

### Finding Description
`refund()` is a fully permissionless, signed extrinsic (`ensure_signed(origin)?`, no privileged role) that anyone can call to progress a crowdloan's refund once the crowdloan has ended [2](#0-1) . It iterates over the contribution child-trie via `contribution_iterator`, and for each entry does:

```rust
CurrencyOf::<T>::transfer(&fund_account, &who, balance, AllowDeath)?;
CurrencyOf::<T>::reactivate(balance);
Self::contribution_kill(fund.fund_index, &who);
fund.raised = fund.raised.saturating_sub(balance);
refund_count += 1;
``` [3](#0-2) 

The `?` on `transfer` means any failure aborts the whole `refund()` call. Under `pallet_balances`'s `Currency::transfer`, crediting a *dead* account (zero providers) with an amount below `ExistentialDeposit` fails with an `ExistentialDeposit`/`FundsUnavailable`-class error rather than silently succeeding. A contributor's account can become dead between `contribute()` and `refund()` (e.g. the user withdraws/transfers away all of their other free balance elsewhere, causing account reaping), while the stored contribution balance for that account in the crowdloan child trie remains whatever was contributed — potentially small, depending on the runtime's `MinContribution` relative to `ExistentialDeposit`.

Because FRAME wraps every extrinsic dispatch in an implicit storage transaction that is rolled back on `Err`, the failing transfer does not merely skip that one contributor: it reverts `contribution_kill`/`fund.raised` updates for *every contributor processed earlier in that same call*, and since `contribution_iterator` iterates the child trie in a fixed deterministic order and previously-refunded entries are removed, the still-poisoned entry will be re-encountered (and re-fail) on every future `refund()` call, permanently blocking refunds for the remainder of the trie. This is structurally the same failure class as the audited report: one non-cooperating/edge-case recipient in a shared batch-settlement loop bricks the whole settlement for all others, and (as in the original report) also blocks fund lifecycle completion — `dissolve()` requires `fund.raised.is_zero()` [4](#0-3) , so the depositor's `SubmissionDeposit` can never be recovered either.

### Impact Explanation
If triggered, the fund can never fully refund, `PartiallyRefunded`/no-progress state persists forever for every entry after the poisoned one, and `dissolve()` is permanently unreachable, permanently freezing both the remaining contributors' funds and the fund creator's `SubmissionDeposit`. This matches the "loss/freezing of funds affecting all other participants due to one bad account" pattern in the source report.

### Likelihood Explanation
This is conditional and I could not fully confirm exploitability in this session: the failure only manifests if a contributor's stored crowdloan balance can be smaller than `ExistentialDeposit` (i.e. `MinContribution < ExistentialDeposit` for that runtime) *and* the attacker deliberately reaps their own account after contributing but before refund. I queried but did not get to compare the concrete `MinContribution`/`ExistentialDeposit` constants configured in `polkadot/runtime/rococo/src/lib.rs` and `polkadot/runtime/westend/src/lib.rs` before running out of tool budget, so I cannot confirm whether any currently-live Parity runtime satisfies this precondition. Without that confirmation this should be treated as a plausible but **unverified** Medium/Low-likelihood finding rather than a proven live exploit.

### Recommendation
Do not let a single contributor's transfer failure abort the whole `refund()` batch: catch/skip failing transfers (e.g. via `defensive`/best-effort handling similar to `T::Currency::release(..., BestEffort)` used elsewhere in this codebase, see `substrate/frame/nis/src/lib.rs` for the pattern), log/emit an event for the failed entry, and continue processing the remaining contributors so a single stuck account cannot block the rest of the fund from being refunded and dissolved.

### Proof of Concept
Not executed. A concrete integration reproduction would require: (1) confirming a runtime configuration where `MinContribution < ExistentialDeposit`, (2) `contribute()` from an account whose contribution is below ED, (3) fully draining/reaping that account's other free balance so it becomes dead before crowdloan end, (4) calling `refund()` with multiple contributors including the reaped one, and asserting that `refund()` errors and that a subsequent call still fails on the same entry while `Funds::raised` never reaches zero. I was not able to run this due to the final-iteration constraint; this should be verified with a Devin session using `polkadot/runtime/common/src/crowdloan/mod.rs` test harness (`polkadot/runtime/common/src/integration_tests.rs`) before treating this as confirmed.

### Citations

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L507-519)
```rust
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::refund(T::RemoveKeysLimit::get()))]
		pub fn refund(
			origin: OriginFor<T>,
			#[pallet::compact] index: ParaId,
		) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;

			let mut fund = Funds::<T>::get(index).ok_or(Error::<T>::InvalidParaId)?;
			let now = frame_system::Pallet::<T>::block_number();
			let fund_account = Self::fund_account_id(fund.fund_index);
			Self::ensure_crowdloan_ended(now, &fund_account, &fund)?;

```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L520-536)
```rust
			let mut refund_count = 0u32;
			// Try killing the crowdloan child trie
			let contributions = Self::contribution_iterator(fund.fund_index);
			// Assume everyone will be refunded.
			let mut all_refunded = true;
			for (who, (balance, _)) in contributions {
				if refund_count >= T::RemoveKeysLimit::get() {
					// Not everyone was able to be refunded this time around.
					all_refunded = false;
					break;
				}
				CurrencyOf::<T>::transfer(&fund_account, &who, balance, AllowDeath)?;
				CurrencyOf::<T>::reactivate(balance);
				Self::contribution_kill(fund.fund_index, &who);
				fund.raised = fund.raised.saturating_sub(balance);
				refund_count += 1;
			}
```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L562-571)
```rust
			// Only allow dissolution when the raised funds goes to zero,
			// and the caller is the fund creator or we are past the end date.
			let permitted = who == fund.depositor || now >= fund.end;
			let can_dissolve = permitted && fund.raised.is_zero();
			ensure!(can_dissolve, Error::<T>::NotReadyToDissolve);

			// Assuming state is not corrupted, the child trie should already be cleaned up
			// and all funds in the crowdloan account have been returned. If not, governance
			// can take care of that.
			debug_assert!(Self::contribution_iterator(fund.fund_index).count().is_zero());
```
