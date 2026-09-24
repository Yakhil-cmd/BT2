### Title
`claim_child_bounty` silently ignores failed curator/beneficiary payouts because checks use `debug_assert!` instead of propagating the `Result` - ([File: substrate/frame/child-bounties/src/lib.rs])

### Summary
The Sherlock report flags an "unchecked send" pattern: a Solidity `transfer()` return value is discarded, so a failed payout does not halt execution and funds can be considered spent even though they never moved. The Polkadot SDK analog is in `pallet-child-bounties`'s `claim_child_bounty`, where the `DispatchResult` of both the curator-fee transfer and the beneficiary transfer is captured and only checked with `debug_assert!`, which is compiled out entirely in release/production builds. If either `T::Currency::transfer` call returns `Err(..)`, execution proceeds unchanged: the `Claimed` event fires, the child-bounty record is deleted from storage, and the extrinsic returns `Ok(())`.

### Finding Description
`claim_child_bounty` is a permissionless, signed extrinsic — "The dispatch origin for this call may be any signed origin" [1](#0-0) . Inside the `try_mutate_exists` closure it performs two balance transfers and "checks" their results only via `debug_assert!`: [2](#0-1) 

```rust
let fee_transfer_result = T::Currency::transfer(
    &child_bounty_account, curator, curator_fee, AllowDeath,
);
debug_assert!(fee_transfer_result.is_ok());

let payout_transfer_result = T::Currency::transfer(
    &child_bounty_account, beneficiary, payout, AllowDeath,
);
debug_assert!(payout_transfer_result.is_ok());
```

`debug_assert!` is a no-op when `debug_assertions` is disabled, which is the standard configuration for production runtime builds (release WASM/native builds do not enable `debug-assertions`). Consequently, in a production runtime the `Result` returned by `Currency::transfer` — a `#[must_use]`-style `DispatchResult` that Rust would otherwise force the developer to handle — is effectively discarded, exactly mirroring the reported issue where an ERC20 `transfer` return value is ignored: execution continues regardless of transfer success or failure.

After the (possibly failed) transfers, the closure unconditionally:
- emits `Event::Claimed { .. }` with the intended `payout` amount,
- decrements `ParentChildBounties`,
- removes `ChildBountyDescriptionsV1`,
- sets `*maybe_child_bounty = None`, deleting the only on-chain record referencing `child_bounty_account`,

and returns `Ok(())` [3](#0-2) .

A concrete failure trigger for the beneficiary transfer: `T::Currency::transfer(..., AllowDeath)` still enforces the destination's existential deposit when creating a new account. If `beneficiary` has no existing account and `payout` is below the chain's `ExistentialDeposit`, the transfer returns `Err(Token(BelowMinimum))` (or similar), yet this failure is swallowed by the compiled-out `debug_assert!`. The funds remain stranded in `child_bounty_account` (computed by `Self::child_bounty_account_id(parent_bounty_id, child_bounty_id)`), but because the child-bounty record has just been deleted, no other dispatchable in this pallet references that specific derived account to recover the balance — unlike `pallet-bounties`, which has an explicit `reclaim_bounty_funds` sweep for closed bounties, `pallet-child-bounties` has no equivalent function.

### Impact Explanation
This causes silent loss of accountability for treasury-derived funds: the chain state asserts a payout was completed (event emitted, bounty removed) while the actual transfer failed and the funds are stuck in an now-untracked derived account. This is a fund-freezing/integrity issue rather than direct attacker profit, since the caller of `claim_child_bounty` does not receive anything extra by triggering the failure — but it breaks the invariant that "Claimed" implies funds moved, and can permanently orphan treasury-sourced balance with no dispatchable path to recover it, which aligns with a Medium-severity impact (matching the original report's classification) rather than a Critical/High theft.

### Likelihood Explanation
Reachability requires only a normal signed call to `claim_child_bounty` once a child bounty is in `PendingPayout` state; no privileged role, governance action, or malicious node is needed [4](#0-3) . Triggering the specific "payout below ED to a nonexistent account" failure requires the curator (who sets the payout amount via `award_child_bounty`, not shown here but referenced in the module docs) to pick a beneficiary/payout combination that fails ED — a low-cost, deterministic condition rather than a race or flooding attack.

### Recommendation
Replace both `debug_assert!` checks with real error propagation, e.g.:
```rust
T::Currency::transfer(&child_bounty_account, curator, curator_fee, AllowDeath)
    .map_err(|_| Error::<T>::CuratorFeeTransferFailed)?;
T::Currency::transfer(&child_bounty_account, beneficiary, payout, AllowDeath)
    .map_err(|_| Error::<T>::PayoutTransferFailed)?;
```
so that a failed transfer aborts the whole `try_mutate_exists` closure (rolling back the storage removal) instead of silently proceeding. Additionally, consider adding a permissionless sweep/reclaim path (analogous to `pallet-bounties::reclaim_bounty_funds`) for any residual balance left in a `child_bounty_account` after closure, in case ED or other transfer failures occur despite the fix.

### Proof of Concept
I was not able to execute a live Rust/FRAME integration test in this environment (no filesystem/terminal execution available in ask-only mode); this finding is based on static code reading of `substrate/frame/child-bounties/src/lib.rs` (lines 668-771) confirming: (1) `claim_child_bounty` has no origin privilege check beyond `ensure_signed`, (2) both transfer results are only checked via `debug_assert!` which is stripped in non-debug builds, and (3) the child-bounty record and its derived account are deleted from tracked storage unconditionally afterward, with no equivalent `reclaim_bounty_funds`-style sweep in this pallet (confirmed absent via search). A full reproduction would require building a mock runtime with `debug-assertions = false` (matching production profile), creating a child bounty with a `payout` set below the runtime's `ExistentialDeposit` to a brand-new `beneficiary` account, driving it to `PendingPayout`, and calling `claim_child_bounty`, then asserting the `Claimed` event fires and the child-bounty record is removed while `beneficiary`'s balance remains zero and `child_bounty_account`'s balance retains the undelivered `payout`.

### Citations

**File:** substrate/frame/child-bounties/src/lib.rs (L668-691)
```rust
		/// Claim the payout from an awarded child-bounty after payout delay.
		///
		/// The dispatch origin for this call may be any signed origin.
		///
		/// Call works independent of parent bounty state, No need for parent
		/// bounty to be in active state.
		///
		/// The Beneficiary is paid out with agreed bounty value. Curator fee is
		/// paid & curator deposit is unreserved.
		///
		/// Child-bounty must be in "PendingPayout" state, for processing the
		/// call. And instance of child-bounty is removed from the state on
		/// successful call completion.
		///
		/// - `parent_bounty_id`: Index of parent bounty.
		/// - `child_bounty_id`: Index of child bounty.
		#[pallet::call_index(5)]
		#[pallet::weight(<T as Config>::WeightInfo::claim_child_bounty())]
		pub fn claim_child_bounty(
			origin: OriginFor<T>,
			#[pallet::compact] parent_bounty_id: BountyIndex,
			#[pallet::compact] child_bounty_id: BountyIndex,
		) -> DispatchResult {
			ensure_signed(origin)?;
```

**File:** substrate/frame/child-bounties/src/lib.rs (L714-745)
```rust
						// Make curator fee payment.
						let child_bounty_account =
							Self::child_bounty_account_id(parent_bounty_id, child_bounty_id);
						let balance = T::Currency::free_balance(&child_bounty_account);
						let curator_fee = child_bounty.fee.min(balance);
						let payout = balance.saturating_sub(curator_fee);

						// Unreserve the curator deposit. Should not fail
						// because the deposit is always reserved when curator is
						// assigned.
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

```

**File:** substrate/frame/child-bounties/src/lib.rs (L746-765)
```rust
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

						Ok(())
```
