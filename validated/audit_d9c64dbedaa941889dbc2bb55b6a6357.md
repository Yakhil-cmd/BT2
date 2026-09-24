### Title
Permanent DoS of `Crowdloan::refund` when a single contributor's refund transfer fails - ([File: polkadot/runtime/common/src/crowdloan/mod.rs])

### Summary
`pallet_crowdloan`'s permissionless `refund` extrinsic iterates over a fund's contributors in a fixed order and issues a `Currency::transfer` to each one inside the loop, propagating any transfer failure with `?`. Because a single failing transfer aborts the whole dispatchable (and FRAME rolls back all storage writes made during that call), one contributor whose refund transfer permanently fails can block refunds for every other contributor in the fund — the same root cause as the reported CrabNetting issue (sequential, un-skippable payout loop with no per-recipient failure isolation), but expressed through the ED/dead-account failure mode of `pallet_balances::Currency::transfer` rather than an ERC-20 blocklist.

### Finding Description
`Crowdloan::refund` (`polkadot/runtime/common/src/crowdloan/mod.rs:509-550`) does:
```rust
for (who, (balance, _)) in contributions {
    if refund_count >= T::RemoveKeysLimit::get() {
        all_refunded = false;
        break;
    }
    CurrencyOf::<T>::transfer(&fund_account, &who, balance, AllowDeath)?;
    CurrencyOf::<T>::reactivate(balance);
    Self::contribution_kill(fund.fund_index, &who);
    fund.raised = fund.raised.saturating_sub(balance);
    refund_count += 1;
}
``` [1](#0-0) 

Any user can `contribute` to a live crowdloan with a signed extrinsic [2](#0-1) , i.e. this is real, permitted, fee-paying user input with no privileged role required. Anyone (also permissionless) can later call `refund` to trigger mass payout to all contributors [3](#0-2) .

`Currency::transfer(..., AllowDeath)` only allows the *sender* (the fund pot account) to be reaped; it does not waive the existential-deposit requirement on the *recipient*. If the recipient account no longer exists (e.g. it was reaped after contributing, by later spending/transferring away its own balance) and the refunded `balance` is below the chain's `ExistentialDeposit`, the transfer call returns `Err(Error::ExistentialDeposit)`. Because the `?` operator propagates this error out of the dispatchable, and FRAME automatically rolls back all storage mutations of a dispatchable that returns `Err` (including any `contribution_kill` and partial refunds already performed earlier in the *same* loop iteration), the fund's contributor list is left completely unchanged. On every subsequent call to `refund`, the iterator (`contribution_iterator`, over a child-trie keyed by hashed account id) presents contributors in the same order, so the same account is hit again at the same point and the same abort happens — a deterministic, indefinite block.

This is structurally identical to the CrabNetting root cause: a strictly sequential, all-or-nothing payout loop over a list that an attacker fully controls their own position in, with no mechanism to skip/quarantine one bad entry, causing legitimate unrelated participants (all other contributors of the crowdloan) to be permanently denied their refund.

### Impact Explanation
If reachable, this would permanently freeze *all* remaining contributors' funds in a specific crowdloan's pot account — an irreversible freezing of funds for third parties who did nothing wrong, matching the "irreversible freezing" class the audit criteria prioritize. Depending on `RemoveKeysLimit` versus fund size, this could block refunds for the entire fund in a single failing call, or block progress at whatever position the "poisoned" contribution occupies.

### Likelihood Explanation
I could not fully verify two preconditions needed to turn this into a demonstrable exploit, and I want to be explicit about that rather than assert them as fact:
1. Whether `do_contribute`'s `MinContribution` check (referenced in `polkadot/runtime/common/src/crowdloan/mod.rs`, confirmed present via grep but not read in detail) permits a contribution amount that, after a partial/complete drain of the contributor's own account later, ends up below `ExistentialDeposit` at refund time. It is very plausible: a user can contribute early (when they hold plenty of balance) and only later spend down/transfer away their own remaining balance to get reaped, independent of the crowdloan's `MinContribution`.
2. Whether the crowdloan/slot-auction pallet is still live/enabled on current Polkadot/Kusama production runtimes given the migration to Agile Coretime (auctions were deprecated). This directly affects "matching live Parity bounty program" eligibility per the audit's requirements, and I was not able to confirm current deployment status from the code available to me.

Given standard FRAME semantics (dispatchable failure = full storage rollback) and the well-known ED requirement on `Currency::transfer` recipients, the core DoS mechanism itself is sound; the open questions are about exploit setup cost and current on-chain relevance, not about the code path's existence.

### Recommendation
- In `Crowdloan::refund`, do not propagate individual transfer failures with `?`. Instead, catch the error per-contributor (e.g. via `let _ = ...` combined with an explicit skip/park mechanism), emit a `RefundFailed`-style event, and continue processing the remaining contributors, similar to how `pallet_message_queue` isolates per-message failures (`substrate/frame/message-queue/src/tests.rs:171-215` illustrates the desired behavior pattern of not letting one bad item block the queue) [4](#0-3) .
- Alternatively, use `keep_alive`/`ExistenceRequirement::AllowDeath` semantics that guarantee success (e.g. `deposit_creating`/force-credit path) for refunds, since the pot is a system-controlled account and dust amounts should not block collective payouts.
- Add a privileged/governance escape hatch (`force_refund_skip`/`urgent_dequeue`-style call, mirroring the CrabNetting recommendation) so an unrecoverable single-entry failure can be manually bypassed without requiring a runtime upgrade.

### Proof of Concept
I did not execute a Rust/FRAME integration test to confirm this end-to-end, and I explicitly flag this as unverified rather than claiming a successful run. A concrete reproduction would need to:
1. Deploy `pallet_crowdloan` in a test runtime with a small `ExistentialDeposit`.
2. Have account `A` contribute a small amount to a fund, then have `A` transfer away the rest of its balance elsewhere (via `pallet_balances::transfer_allow_death`) so that `A`'s account is reaped (zero providers) before the crowdloan ends.
3. Have other accounts `B`, `C`, ... contribute normally.
4. End the crowdloan lease/period and call `Crowdloan::refund` permissionlessly.
5. Assert: the extrinsic returns `Err(Error::ExistentialDeposit)` (propagated through `pallet_crowdloan`'s `?`), and confirm via storage inspection that `B`, `C`'s contributions are still present (i.e., the whole batch was rolled back), and that this repeats on every subsequent call to `refund`.

I was not able to execute this test in the current session (no tool access to run Rust test harnesses), so this PoC is a design for a background engineer to run, not a completed verification. The severity/likelihood assessment above should be treated as provisional until (a) the ED/dead-account failure of `Currency::transfer` is confirmed against the exact runtime configuration in use, and (b) the crowdloan pallet's current live deployment status on a Parity-run/bounty-eligible chain is confirmed.

### Citations

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L446-454)
```rust
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

**File:** substrate/frame/message-queue/src/tests.rs (L171-215)
```rust
#[test]
fn service_queues_failing_messages_works() {
	use MessageOrigin::*;
	build_and_execute::<Test>(|| {
		set_weight("service_page_item", 1.into_weight());
		MessageQueue::enqueue_message(msg("badformat"), Here);
		MessageQueue::enqueue_message(msg("corrupt"), Here);
		MessageQueue::enqueue_message(msg("unsupported"), Here);
		MessageQueue::enqueue_message(msg("stacklimitreached"), Here);
		MessageQueue::enqueue_message(msg("yield"), Here);
		// Starts with four pages.
		assert_pages(&[0, 1, 2]);

		assert_eq!(MessageQueue::service_queues(1.into_weight()), 1.into_weight());
		assert_last_event::<Test>(
			Event::ProcessingFailed {
				id: blake2_256(b"badformat").into(),
				origin: MessageOrigin::Here,
				error: ProcessMessageError::BadFormat,
			}
			.into(),
		);
		assert_eq!(MessageQueue::service_queues(1.into_weight()), 1.into_weight());
		assert_last_event::<Test>(
			Event::ProcessingFailed {
				id: blake2_256(b"corrupt").into(),
				origin: MessageOrigin::Here,
				error: ProcessMessageError::Corrupt,
			}
			.into(),
		);
		assert_eq!(MessageQueue::service_queues(1.into_weight()), 1.into_weight());
		assert_last_event::<Test>(
			Event::ProcessingFailed {
				id: blake2_256(b"unsupported").into(),
				origin: MessageOrigin::Here,
				error: ProcessMessageError::Unsupported,
			}
			.into(),
		);
		assert_eq!(MessageQueue::service_queues(1.into_weight()), 1.into_weight());
		assert_eq!(System::events().len(), 4);
		// Last page with the `yield` stays in.
		assert_pages(&[2]);
	});
```
