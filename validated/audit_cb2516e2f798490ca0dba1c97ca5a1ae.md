Found a strong analog in `pallet-nfts`. This is the exact same bug class already fixed in `pallet-assets::transfer_ownership` (via `pr_12366`) but left unpatched in `pallet-nfts::do_transfer_ownership` / `do_force_collection_owner`.

### Title
`pallet-nfts::do_transfer_ownership` discards the `repatriate_reserved` remainder, permanently stranding the collection deposit as reserved balance on the old owner - ([File: substrate/frame/nfts/src/features/transfer.rs])

### Summary
`Currency::repatriate_reserved` is a `BestEffort` operation: it moves as much of the reserved amount as it can and returns any un-moved remainder, without erroring [1](#0-0) . `pallet-nfts::do_transfer_ownership` calls this and discards the returned value with `?` alone, assuming the full `owner_deposit` was moved, then unconditionally flips `details.owner` to the new account and drops `dec_consumers`/`CollectionAccount` bookkeeping for the old owner [2](#0-1) . The identical unfixed pattern exists in `do_force_collection_owner` [3](#0-2) .

### Finding Description
`pallet-balances`'s `do_transfer_reserved`, which backs `repatriate_reserved`, computes `max = reducible_total_balance_on_hold(slashed, Polite)` and clamps the moved amount to `value.min(max)` under `BestEffort` precision, returning only the actually-moved amount; the caller must inspect `value.saturating_sub(actual)` to detect a partial move [4](#0-3) . Under `Fortitude::Polite`, if the old owner has a lock/freeze that overlaps with their free balance (e.g., from staking, vesting, or any other pallet using `LockableCurrency`), part of the reserved `owner_deposit` becomes "untouchable" and cannot be repatriated — exactly the invariant violated in the report's `pos.underlyingAmount` clamp.

This is a documented and already-remediated bug class in this same codebase: `pallet-assets::transfer_ownership` had the identical flaw and was hardened to capture the remainder and reject the call with `IncompleteDepositTransfer` if non-zero [5](#0-4) , as documented in the corresponding prdoc [6](#0-5) . `pallet-nfts::do_transfer_ownership`/`do_force_collection_owner` were never given the equivalent fix.

Any signed extrinsic user who is a collection owner can trigger this: `NFTs::transfer_ownership` is a normal signed dispatchable that calls `do_transfer_ownership` after the destination account opts in via `set_accept_ownership`. The attacker (the collection owner) controls their own `owner_deposit` reservation, and can acquire an overlapping lock (e.g., by staking/bonding, or receiving a vesting schedule) on the same account, causing the `Polite` reducible-hold check to leave part of the deposit stuck.

### Impact Explanation
Once `details.owner` is switched to the new account, `Collection::<T,I>` no longer references the old owner for that deposit, and `CollectionAccount` for the old owner is removed. The un-repatriated remainder stays reserved on the old owner's account under the generic (unnamed) `Currency::reserve` mechanism, with no `pallet-nfts` storage record left pointing to it and no code path in the pallet that will ever call `unreserve` for it again. The funds are not stolen by a third party, but they become **irrecoverably frozen** — an accounting break where the recorded/expected deposit (now owned by the new owner conceptually) diverges from what was actually collected, and the old owner's own balance is durably locked with no dispatchable recovery route (differs from the report's "other users' funds get locked in a shared vault," but matches the "irreversible freezing" class explicitly called out as acceptable in the bounty guidance).

### Likelihood Explanation
Exploitability requires the old owner's account to simultaneously hold (a) a reserved `owner_deposit` for an NFT collection and (b) a lock/freeze whose `frozen` amount overlaps their `free` balance sufficiently to reduce `reducible_total_balance_on_hold` below the deposit amount. Both conditions are attacker-achievable with ordinary, unprivileged extrinsics (e.g., `Staking::bond`, `Vesting`), matching the precise reproduction pattern already validated and fixed for `pallet-assets` in this codebase (see `transfer_ownership_fails_when_deposit_is_locked` test) [7](#0-6) . No governance, root, or privileged role is required.

### Recommendation
In `pallet-nfts::features::transfer.rs`, capture the `Balance` returned by `repatriate_reserved` in both `do_transfer_ownership` and `do_force_collection_owner`, and `ensure!` it is zero (returning a new `IncompleteDepositTransfer`-style error and aborting the `try_mutate` on failure) before flipping `details.owner`, mirroring the fix already applied to `pallet-assets::transfer_ownership`.

### Proof of Concept
Not executed. Based on static analysis: the code path and root cause are structurally identical to the already-patched `pallet-assets` case (verified by the corresponding fix, prdoc, and regression test `transfer_ownership_fails_when_deposit_is_locked` in this same repository), but I did not run a local Rust/FRAME integration test against `pallet-nfts::do_transfer_ownership` to confirm the exact numeric clamp behavior for this pallet's specific `Config`/mock, so this should be treated as a **structural analog pending PoC confirmation** rather than a demonstrated exploit. Severity is capped below the original report's High rating because the frozen funds here belong to the attacker's own account (self-inflicted, irreversible freeze) rather than draining a shared vault used by other depositors — this weakens, but per program guidance does not eliminate, eligibility as an "irreversible freezing" finding.

### Citations

**File:** substrate/frame/balances/src/impl_currency.rs (L725-734)
```rust
	fn repatriate_reserved(
		slashed: &T::AccountId,
		beneficiary: &T::AccountId,
		value: Self::Balance,
		status: Status,
	) -> Result<Self::Balance, DispatchError> {
		let actual =
			Self::do_transfer_reserved(slashed, beneficiary, value, BestEffort, Polite, status)?;
		Ok(value.saturating_sub(actual))
	}
```

**File:** substrate/frame/nfts/src/features/transfer.rs (L142-161)
```rust
			// Move the deposit to the new owner.
			T::Currency::repatriate_reserved(
				&details.owner,
				&new_owner,
				details.owner_deposit,
				Reserved,
			)?;

			// Update account ownership information.
			CollectionAccount::<T, I>::remove(&details.owner, &collection);
			CollectionAccount::<T, I>::insert(&new_owner, &collection, ());

			details.owner = new_owner.clone();
			OwnershipAcceptance::<T, I>::remove(&new_owner);
			frame_system::Pallet::<T>::dec_consumers(&new_owner);

			// Emit `OwnerChanged` event.
			Self::deposit_event(Event::OwnerChanged { collection, new_owner });
			Ok(())
		})
```

**File:** substrate/frame/nfts/src/features/transfer.rs (L216-222)
```rust
			// Move the deposit to the new owner.
			T::Currency::repatriate_reserved(
				&details.owner,
				&owner,
				details.owner_deposit,
				Reserved,
			)?;
```

**File:** substrate/frame/balances/src/lib.rs (L1265-1277)
```rust
		) -> Result<T::Balance, DispatchError> {
			if value.is_zero() {
				return Ok(Zero::zero());
			}

			let max = <Self as fungible::InspectHold<_>>::reducible_total_balance_on_hold(
				slashed, fortitude,
			);
			let actual = match precision {
				Precision::BestEffort => value.min(max),
				Precision::Exact => value,
			};
			ensure!(actual <= max, TokenError::FundsUnavailable);
```

**File:** substrate/frame/assets/src/lib.rs (L1343-1347)
```rust
				// `repatriate_reserved` is best-effort: reject any partial move so the recorded
				// deposit stays in sync with what is actually reserved on the owner.
				let remaining =
					T::Currency::repatriate_reserved(&details.owner, &owner, deposit, Reserved)?;
				ensure!(remaining.is_zero(), Error::<T, I>::IncompleteDepositTransfer);
```

**File:** prdoc/pr_12366.prdoc (L1-14)
```text
title: 'pallet-assets: enforce full deposit transfer in transfer_ownership'
doc:
- audience: Runtime Dev
  description: |-
    `transfer_ownership` previously discarded the remainder returned by `repatriate_reserved`.
    Under `Polite` fortitude, a lock or freeze on the current owner that overlaps their free
    balance can leave part of the reserved deposit behind, leaving the asset's recorded deposit
    out of sync with what is actually reserved. The call now captures the returned remainder and
    rejects the dispatch with a new `IncompleteDepositTransfer` error when it is non-zero;
    the storage layer rolls back the partial move. To recover, the current owner must clear or
    reduce the offending locks/freezes and retry.
crates:
- name: pallet-assets
  bump: major
```

**File:** substrate/frame/assets/src/tests.rs (L992-1020)
```rust
#[test]
fn transfer_ownership_fails_when_deposit_is_locked() {
	build_and_execute(|| {
		Balances::make_free_balance_be(&1, 100);
		Balances::make_free_balance_be(&2, 100);
		// Reserves 1 from owner 1: free=99, reserved=1.
		assert_ok!(Assets::create(RuntimeOrigin::signed(1), 0, 1, 1));
		assert_eq!(Balances::free_balance(&1), 99);
		assert_eq!(Balances::reserved_balance(&1), 1);

		// Lock the owner's full balance, so frozen=100 > free=99 and 1 unit of the
		// reserve becomes immovable under `Polite` repatriation.
		Balances::set_lock(*b"test/lk0", &1, 100, WithdrawReasons::all());

		assert_noop!(
			Assets::transfer_ownership(RuntimeOrigin::signed(1), 0, 2),
			Error::<Test>::IncompleteDepositTransfer,
		);
		// State is rolled back: original owner still holds the deposit.
		assert_eq!(Balances::reserved_balance(&1), 1);
		assert_eq!(Balances::reserved_balance(&2), 0);

		// Clearing the lock unblocks the call.
		Balances::remove_lock(*b"test/lk0", &1);
		assert_ok!(Assets::transfer_ownership(RuntimeOrigin::signed(1), 0, 2));
		assert_eq!(Balances::reserved_balance(&1), 0);
		assert_eq!(Balances::reserved_balance(&2), 1);
	});
}
```
