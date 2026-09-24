### Title
`claim_bounty`/`claim_child_bounty` silently drop transfer failures and permanently delete the bounty record, losing the beneficiary's payout - ([File: substrate/frame/bounties/src/lib.rs])

### Summary
The reported Vault.vy issue is that a claim function transfers funds to a claimant without checking whether the transfer can succeed, causing the call to revert. The closest demonstrable analog in this Polkadot SDK checkout is worse than the original report: `pallet-bounties::claim_bounty` and `pallet-child-bounties::claim_child_bounty` perform the payout transfer, discard the `Result` via `debug_assert!` (a no-op in release/production builds), and then unconditionally delete the bounty/child-bounty storage entry regardless of whether the transfer actually succeeded.

### Finding Description
In `claim_bounty` (`substrate/frame/bounties/src/lib.rs`), after computing `payout`, the code does: [1](#0-0) 
`T::Currency::transfer(&bounty_account, &beneficiary, payout, AllowDeath)` is called and its `Result` is only checked with `debug_assert!(res.is_ok())`, which compiles to nothing in a `--release`/production runtime build (the default for real chains). Immediately afterward, `*maybe_bounty = None;` unconditionally deletes the bounty record, and `BountyDescriptions::<T, I>::remove(bounty_id)` and `T::ChildBountyManager::bounty_removed(bounty_id)` run regardless of whether the beneficiary was actually paid. The same pattern exists in `claim_child_bounty`: [2](#0-1) 

The legacy `Currency::transfer` implementation enforces the existential deposit on the **receiving** account: if `payout` is smaller than `T::Currency::minimum_balance()` and the `beneficiary` account does not already exist, the deposit fails (an "ExistentialDeposit" style error), so the whole `transfer` call returns `Err`. Because that `Err` is discarded by `debug_assert!`, the extrinsic proceeds as if the payment succeeded: it emits `Event::BountyClaimed` with the (unpaid) `payout` amount and deletes the bounty. There is no re-claim path afterward since the storage record backing the claim is gone. This is the same root-cause invariant violation as the reported bug — "insufficient/failed transfer to the claimant is not handled" — but instead of just reverting (DoS), the fund/entitlement is silently and permanently lost.

Notably, this exact class of bug (discarding the transfer error and deleting the claim entitlement) was previously identified and fixed for `pallet-broker`'s `do_claim_revenue`, per the changelog: [3](#0-2) 
and the corresponding fix now properly propagates the error with `?` so the whole extrinsic (and its storage mutations) is rolled back atomically: [4](#0-3) 
That fix and its regression test explicitly establish the expected invariant for this class of pallet code: [5](#0-4) 
The bounties/child-bounties pallets were not updated to follow this same pattern and still rely on `debug_assert!` around the payout transfer instead of propagating the error.

### Impact Explanation
If the transfer to the beneficiary (or curator) fails for any reason not anticipated by the "should not fail" comments — most plausibly the beneficiary account not existing and the payout being below the existential deposit — the beneficiary receives nothing, yet the bounty (and its associated deposits/records) is permanently deleted from storage with `BountyClaimed`/`Claimed` still emitted. The entitlement cannot be re-claimed. This is a fund-loss/entitlement-loss bug, more severe than the reported Medium-severity DoS-on-claim in the original report, because in FRAME a normal DispatchError would atomically roll back state (unlike the Vyper contract), but here the error is deliberately suppressed so the rollback never triggers.

### Likelihood Explanation
This requires no privileged role: the caller of `claim_bounty`/`claim_child_bounty` is any signed account ("anyone can trigger claim"), and the beneficiary/curator identities are set earlier via ordinary bounty-award flow. The triggering condition (final payout amount below the chain's `ExistentialDeposit` while the beneficiary account does not yet exist) is a normal, reachable configuration for small bounties/child-bounties, not a contrived edge case requiring governance or validator collusion. However, I could not run an actual integration test in this environment to observe the exact runtime error variant that `Currency::transfer` returns in this scenario (I was only able to confirm the code path and the trait documentation semantics, not execute a reproduction), so exploitability specifically hinges on confirming the balances implementation actually errors here rather than silently truncating/rounding.

### Recommendation
Replace the `debug_assert!(res.is_ok())` pattern in `claim_bounty` and `claim_child_bounty` with proper error propagation (`?`) inside the `try_mutate_exists` closure, mirroring the fix applied to `pallet-broker`'s `do_claim_revenue` in `prdoc/pr_13040.prdoc`. This ensures that if the payout transfer fails, the whole extrinsic reverts, the bounty/child-bounty record is preserved, and the beneficiary retains the ability to claim once conditions allow (e.g., using `KeepAlive`/`Preserve` semantics or ensuring minimum payout amounts), rather than silently deleting the entitlement.

### Proof of Concept
Not executed. I identified the code path and the analogous already-fixed vulnerability in `pallet-broker`, and inspected the transfer/ED semantics conceptually, but did not build/run a Rust integration test against `pallet-bounties`/`pallet-child-bounties` mock runtimes to trigger the exact existential-deposit failure and observe the resulting state (bounty deleted, beneficiary unpaid). This would need to be done in an environment with cargo/test execution access — set a bounty/child-bounty payout below the mock runtime's `ExistentialDeposit`, ensure the beneficiary account has zero balance, call `claim_bounty`/`claim_child_bounty` in a `--release`-equivalent test configuration (debug_assertions disabled) and assert that `BountyClaimed`/`Claimed` fires and the bounty record is removed while the beneficiary's balance remains zero.

### Citations

**File:** substrate/frame/bounties/src/lib.rs (L820-828)
```rust
					let final_fee = fee.saturating_sub(children_fee);
					let res =
						T::Currency::transfer(&bounty_account, &curator, final_fee, AllowDeath); // should not fail
					debug_assert!(res.is_ok());
					let res =
						T::Currency::transfer(&bounty_account, &beneficiary, payout, AllowDeath); // should not fail
					debug_assert!(res.is_ok());

					*maybe_bounty = None;
```

**File:** substrate/frame/child-bounties/src/lib.rs (L724-763)
```rust
						let _ = T::Currency::unreserve(curator, child_bounty.curator_deposit);

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

**File:** prdoc/pr_13040.prdoc (L1-10)
```text
title: Propagate the revenue claim transfer error
doc:
- audience: Runtime Dev
  description: |-
    Return the error when the revenue payout to the payee fails, so the extrinsic reverts and
    the claimant keeps the entitlement. The pallet previously discarded this error and removed
    the entitlement without payment.
crates:
- name: pallet-broker
  bump: patch
```

**File:** substrate/frame/broker/src/dispatchable_impls.rs (L458-464)
```rust
		if contribution.length > 0 {
			InstaPoolContribution::<T>::insert(region, &contribution);
		}
		// The steps above removed the contribution and reduced the stored payouts. If the
		// transfer fails, the error must revert them. The storage changes and the payment
		// must both happen, or neither.
		T::Currency::transfer(&Self::account_id(), &contribution.payee, payout, Expendable)?;
```

**File:** substrate/frame/broker/src/tests.rs (L3360-3400)
```rust
/// A claim removes the contribution and reduces the stored payouts before it pays the payee.
/// If the payment fails, all of these changes must revert. If they do not, the payee keeps no
/// claim and receives no money, and a later attempt reports `UnknownContribution`.
#[test]
fn claim_revenue_reverts_when_pot_cannot_pay() {
	TestExt::new().endow(1, 1000).execute_with(|| {
		// Give account 2 a claim on pool revenue: reserve a pool core, sell a region to
		// account 1, and pool that region with account 2 as the payee.
		let item = ScheduleItem { assignment: Pool, mask: CoreMask::complete() };
		assert_ok!(Broker::do_reserve(Schedule::truncate_from(vec![item])));
		assert_ok!(Broker::do_start_sales(100, 2));
		advance_to(2);
		let region = Broker::do_purchase(1, u64::max_value()).unwrap();
		assert_ok!(Broker::do_pool(region, None, 2, Final));

		// Account 1 buys and spends credit. This sends revenue to the pot, where 4 units
		// belong to account 2 and stay there until it claims them.
		assert_ok!(Broker::do_purchase_credit(1, 20, 1));
		advance_to(8);
		assert_ok!(TestCoretimeProvider::spend_instantaneous(1, 10));
		advance_to(11);
		assert_eq!(pot(), 4);

		// Empty the pot, so the payout to the payee cannot complete.
		burn_from_pot(pot());
		assert_eq!(pot(), 0);

		// Call the extrinsic. It reverts the storage changes when the payout fails.
		// A direct call to `do_claim_revenue` does not revert them.
		let contribution_before = InstaPoolContribution::<Test>::get(region);
		let history_before: Vec<_> = InstaPoolHistory::<Test>::iter().collect();

		// The claim must fail, and it must leave the claim of account 2 in storage.
		assert_err!(
			Broker::claim_revenue(RuntimeOrigin::signed(2), region, 100),
			TokenError::FundsUnavailable
		);

		assert_eq!(balance(2), 0);
		assert_eq!(InstaPoolContribution::<Test>::get(region), contribution_before);
		assert_eq!(InstaPoolHistory::<Test>::iter().collect::<Vec<_>>(), history_before);
```
