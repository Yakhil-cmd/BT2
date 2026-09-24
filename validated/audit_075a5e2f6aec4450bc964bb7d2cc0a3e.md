### Title
`claim_bounty`/`claim_child_bounty` silently swallow failed payout transfers via `debug_assert!`, permanently stranding funds - ([File: substrate/frame/bounties/src/lib.rs], [File: substrate/frame/child-bounties/src/lib.rs])

### Summary
The reported issue's violated invariant is: *a settlement extrinsic performs multiple balance transfers assumed to never fail; when one legitimately fails, the funds become permanently unrecoverable because the surrounding storage record is deleted and there is no retry/rescue path.* The Polkadot SDK analog is `pallet-bounties::claim_bounty` and `pallet-child-bounties::claim_child_bounty`: both make two consecutive `T::Currency::transfer(..., AllowDeath)` calls to the curator and the beneficiary, guard the results only with `debug_assert!(res.is_ok())` [1](#0-0) , and then unconditionally delete the bounty record (`*maybe_bounty = None;`) regardless of whether those transfers actually succeeded [2](#0-1) . `debug_assert!` is compiled to a no-op in release/production builds, so a failed transfer does not abort the extrinsic and does not surface as an error — it is silently discarded while the bounty's account record is wiped out.

### Finding Description
`claim_bounty` (any signed origin may call it) computes `fee`/`payout` from the bounty sub-account's live balance and issues two transfers:
```rust
let res = T::Currency::transfer(&bounty_account, &curator, final_fee, AllowDeath); // should not fail
debug_assert!(res.is_ok());
let res = T::Currency::transfer(&bounty_account, &beneficiary, payout, AllowDeath); // should not fail
debug_assert!(res.is_ok());
*maybe_bounty = None;
``` [3](#0-2) 

The identical pattern exists in `pallet-child-bounties::claim_child_bounty`:
```rust
let fee_transfer_result = T::Currency::transfer(&child_bounty_account, curator, curator_fee, AllowDeath);
debug_assert!(fee_transfer_result.is_ok());
let payout_transfer_result = T::Currency::transfer(&child_bounty_account, beneficiary, payout, AllowDeath);
debug_assert!(payout_transfer_result.is_ok());
...
*maybe_child_bounty = None;
``` [4](#0-3) 

In a release build, `debug_assert!` is a complete no-op: if `T::Currency::transfer` returns `Err(...)`, the `Result` value is simply dropped and execution continues as if it succeeded. The whole call is wrapped in `try_mutate_exists`, which only rolls back on an `Err` return from the *outer* closure — but the closure itself returns `Ok(())` unconditionally after the transfer attempts, so nothing is rolled back even though a transfer silently failed. The bounty/child-bounty storage entry, description, and curator-deposit bookkeeping are all removed as though the payout succeeded.

This is a stricter, worse variant of the reported `Stream::cancel()` bug: instead of the extrinsic reverting when a transfer fails (which at least preserves recoverability), here the extrinsic *succeeds*, the accounting record that identifies the sub-account's balance as "owed to curator/beneficiary" is destroyed, and the funds are left in the (now orphaned) `bounty_account_id`/`child_bounty_account_id` derived account with no code path left in the pallet to reclaim them for that specific claim. `pallet-bounties` does have a `reclaim_bounty_funds` extrinsic (seen in `reclaim_bounty_funds_works_after_accidental_refund` test) but it operates on bounty indices that no longer exist in storage after `*maybe_bounty = None;`, and is keyed by an id that has already been freed, so it cannot be relied upon to recover the specific failed payout amount tied to a claim that has already been "successfully" processed and removed.

A concrete way `T::Currency::transfer(..., AllowDeath)` can fail here without any privileged actor: pallet-balances rejects a transfer that would create a *new* account (curator or beneficiary has zero prior balance) with an amount below `ExistentialDeposit`. `claim_handles_high_fee` in the test suite shows the fee is capped via `.min(balance)` to avoid *insufficient balance* on the sub-account side [5](#0-4) , but there is no analogous floor/ED check protecting the *destination* account when `final_fee` or `payout` is a small dust amount and the curator/beneficiary account does not already exist on-chain. In that scenario `T::Currency::transfer` returns `Err(Error::<T,I>::ExistentialDeposit)` (or the equivalent `TokenError`), which is exactly the class of "recipient-side transfer rejection" that the original report is about — except here the failure is masked instead of reverting.

### Impact Explanation
When the failure occurs, the bounty is marked `BountyClaimed`/`Claimed` and permanently removed from storage while the actual token transfer to the curator or beneficiary never took place. The funds remain locked in the derived sub-account, which after removal of the bounty entry has no owner reference and no dedicated call path to sweep it for that specific claim. This is an irreversible freezing/loss-of-funds condition reachable by any signed account that triggers `claim_bounty`/`claim_child_bounty` (the call is explicitly permissionless — "anyone can trigger claim") once a bounty is in `PendingPayout` state with a dust-sized fee or payout and a fresh destination account.

### Likelihood Explanation
Likelihood is Medium: it requires a specific but realistic configuration — a curator fee or beneficiary payout smaller than `ExistentialDeposit` combined with that curator/beneficiary account not yet existing on-chain. Curators can set arbitrary (including very small) fees via `propose_curator`/child-bounty curator proposal, and beneficiaries are freely chosen by the curator in `award_bounty`. No governance, root, or privileged capability is needed to trigger the claim itself; only ordinary bounty-lifecycle actions (propose/approve/curator-accept/award, all normal permissioned/curator flows already part of the bounty system) are required to set up the dust-payout condition, after which the (permissionless) `claim_bounty` call exposes the silent-failure path.

### Recommendation
Replace `debug_assert!` with proper error propagation (`?`) for both the fee and payout transfers in `claim_bounty` and `claim_child_bounty`, so that a failed transfer aborts the extrinsic (rolling back `try_mutate_exists`) instead of silently succeeding and deleting the bounty record. Additionally, consider validating that `final_fee`/`payout` amounts satisfy `ExistentialDeposit` for previously-unfunded destination accounts before attempting the transfer, or fall back to a `KeepAlive`-safe/dust-handling strategy (e.g., routing sub-ED amounts to treasury) rather than assuming these transfers can never fail.

### Proof of Concept
Not executed. Reproduction would require: (1) creating and funding a bounty, (2) setting a curator fee (or resulting payout) below the runtime's `ExistentialDeposit`, (3) awarding the bounty to a beneficiary account with no prior on-chain balance, (4) advancing past `unlock_at`, (5) calling `claim_bounty` in a **release**-profile test harness (where `debug_assert!` is compiled out) and observing that `BountyClaimed`/`Claimed` fires, the bounty entry is removed, yet `Balances::free_balance(beneficiary_or_curator)` remains `0` while the bounty sub-account is drained/left with residual dust. This was not run against the repository; the existing test suite (`substrate/frame/bounties/src/tests.rs`, `substrate/frame/child-bounties/src/tests.rs`) only exercises the debug-mode assertions and the balance-capping path (`claim_handles_high_fee`), not the below-ED-to-new-account failure mode, so this specific scenario is unverified by CI and its exact failure semantics under the configured `pallet_balances::Config::ExistentialDeposit` should be confirmed with a dedicated integration test before treating this as fully proven.

### Citations

**File:** substrate/frame/bounties/src/lib.rs (L820-831)
```rust
					let final_fee = fee.saturating_sub(children_fee);
					let res =
						T::Currency::transfer(&bounty_account, &curator, final_fee, AllowDeath); // should not fail
					debug_assert!(res.is_ok());
					let res =
						T::Currency::transfer(&bounty_account, &beneficiary, payout, AllowDeath); // should not fail
					debug_assert!(res.is_ok());

					*maybe_bounty = None;

					BountyDescriptions::<T, I>::remove(bounty_id);
					T::ChildBountyManager::bounty_removed(bounty_id);
```

**File:** substrate/frame/child-bounties/src/lib.rs (L726-763)
```rust
						// Make payout to child-bounty curator.
						// Should not fail because curator fee is always less than bounty value.
						let fee_transfer_result = T::Currency::transfer(
							&child_bounty_account,
							curator,
							curator_fee,
							AllowDeath,
						);
						debug_assert!(fee_transfer_result.is_ok());

						// Make payout to beneficiary.
						// Should not fail.
						let payout_transfer_result = T::Currency::transfer(
							&child_bounty_account,
							beneficiary,
							payout,
							AllowDeath,
						);
						debug_assert!(payout_transfer_result.is_ok());

						// Trigger the Claimed event.
						Self::deposit_event(Event::<T>::Claimed {
							index: parent_bounty_id,
							child_index: child_bounty_id,
							payout,
							beneficiary: beneficiary.clone(),
						});

						// Update the active child-bounty tracking count.
						ParentChildBounties::<T>::mutate(parent_bounty_id, |count| {
							count.saturating_dec()
						});

						// Remove the child-bounty description.
						ChildBountyDescriptionsV1::<T>::remove(parent_bounty_id, child_bounty_id);

						// Remove the child-bounty instance from the state.
						*maybe_child_bounty = None;
```

**File:** substrate/frame/bounties/src/tests.rs (L889-925)
```rust
#[test]
fn claim_handles_high_fee() {
	ExtBuilder::default().build_and_execute(|| {
		Balances::make_free_balance_be(&Treasury::account_id(), 101);
		Balances::make_free_balance_be(&4, 30);
		assert_ok!(Bounties::propose_bounty(RuntimeOrigin::signed(0), 50, b"12345".to_vec()));

		assert_ok!(Bounties::approve_bounty(RuntimeOrigin::root(), 0));

		go_to_block(2);

		assert_ok!(Bounties::propose_curator(RuntimeOrigin::root(), 0, 4, 49));
		assert_ok!(Bounties::accept_curator(RuntimeOrigin::signed(4), 0));

		assert_ok!(Bounties::award_bounty(RuntimeOrigin::signed(4), 0, 3));

		go_to_block(5);

		// make fee > balance
		let res = Balances::slash(&Bounties::bounty_account_id(0), 10);
		assert_eq!(res.0.peek(), 10);

		assert_ok!(Bounties::claim_bounty(RuntimeOrigin::signed(1), 0));

		assert_eq!(
			last_event(),
			BountiesEvent::BountyClaimed { index: 0, payout: 0, beneficiary: 3 }
		);

		assert_eq!(Balances::free_balance(4), 70); // 30 + 50 - 10
		assert_eq!(Balances::free_balance(3), 0);
		assert_eq!(Balances::free_balance(Bounties::bounty_account_id(0)), 0);

		assert_eq!(pallet_bounties::Bounties::<Test>::get(0), None);
		assert_eq!(pallet_bounties::BountyDescriptions::<Test>::get(0), None);
	});
}
```
