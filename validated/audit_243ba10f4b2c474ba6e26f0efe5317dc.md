### Title
`payout_stakers_by_page` marks a reward page as permanently claimed even when the SHER-style pot transfer to a staker fails, silently destroying the reward entitlement - ([File: substrate/frame/staking-async/src/pallet/impls.rs])

### Summary
`do_payout_stakers_by_page` marks a validator/era/page combination as claimed *before* the actual reward transfer happens, and the transfer is performed per-recipient in `payout_from_provider` → `make_payout_from_provider`. If the transfer from the era's `StakerRewards` pot to a staker's (or nominator's) account fails, `make_payout_from_provider` swallows the error (logs it and returns `None`); the outer call never propagates this failure, the extrinsic still returns `Ok`, and the page stays marked as `AlreadyClaimed` forever. This is the exact bug class from the Sherlock report: an entitlement is zeroed out/marked-done irrespective of whether the payment transfer actually succeeded, and — like Sherlock's stake, which cannot be cancelled until the lock period passes — a claimed page can never be retried (`Eras::<T>::is_rewards_claimed` / `AlreadyClaimed` is a one-way flag).

### Finding Description
`do_payout_stakers_by_page` (permissionless, callable by any signed account for any validator/era/page) does: [1](#0-0) 

```
if Eras::<T>::is_rewards_claimed(era, &stash, page) {
    return Err(Error::<T>::AlreadyClaimed...);
}
Eras::<T>::set_rewards_as_claimed(era, &stash, page);
let exposure = Eras::<T>::get_paged_exposure(era, &stash, page)...
```

The page is marked claimed unconditionally, *before* any transfer takes place. Later, for the `dap` (transfer-based) payout path, `payout_from_provider` calls `make_payout_from_provider` for the validator and every nominator on the page: [2](#0-1) 

```
fn make_payout_from_provider(...) -> Option<(BalanceOf<T>, RewardDestination<T::AccountId>)> {
    ...
    if let Err(e) = T::Currency::transfer(
        &staker_rewards_pot,
        &payout_account,
        amount,
        Preservation::Expendable,
    ) {
        log!(error, "Failed to transfer reward from pot for era {:?}, stash {:?}: {:?}", era, stash, e);
        return None;
    }
    ...
    Some((amount, dest))
}
```

Failure here is only logged; the caller `payout_from_provider` treats `None` the same as "nothing to pay" (e.g. zero reward points) and simply skips emitting the `Rewarded` event — the overall extrinsic still succeeds: [3](#0-2) 

Because the page's claimed flag was already set at line 386 before any of this, and `Eras::<T>::is_rewards_claimed`/`set_rewards_as_claimed` provide no un-claim path, the affected staker/nominator can never claim that page again — the reward is permanently lost even though it was computed and "entitled."

A concrete, realistic failure mode for `T::Currency::transfer` with `Preservation::Expendable`: if the destination `payout_account` does not currently exist (e.g. a nominator fully unbonded/reaped their stash before payout was claimed) and the computed `amount` for that page is below `ExistentialDeposit`, the transfer fails with `TokenError::BelowMinimum`/`FundsUnavailable`. This is entirely attacker/user reachable without any privileged role: any account can call `payout_stakers`/`payout_stakers_by_page` for any validator/era/page, and the loss is borne by the nominator whose reward rounds to a sub-ED amount for a reaped account.

This mirrors precisely the pattern already recognized and fixed elsewhere in this same codebase: `pallet-broker`'s `do_claim_revenue` was patched (see `prdoc/pr_13040.prdoc`, "Propagate the revenue claim transfer error") specifically to stop discarding the transfer error and removing the entitlement without payment — the exact same class of defect still exists, unfixed, in `staking-async`'s `payout_from_provider` path. [4](#0-3) 

By contrast, `make_payout_legacy` (the mint-based path) cannot hit this bug the same way since minting essentially cannot fail, but the transfer-based `dap` path (`use_dap_payout`) is squarely affected: [5](#0-4) 

### Impact Explanation
A staker's/nominator's earned era reward can be silently and permanently destroyed: no funds move, the pot keeps the balance, but the page can never be re-claimed because `set_rewards_as_claimed` is a one-way state transition set before payment. This is an unauthorized/irrecoverable loss of user funds triggered purely by ordinary, permissionless dispatch (anyone can call `payout_stakers_by_page`), which fits the "irreversible freezing"/fund-loss category the assignment prioritizes. It does not require any privileged role, forged proof, or malicious validator/collator — only a routine reward payout hitting a transfer failure (e.g., sub-ED payout to a reaped account, or an underfunded `StakerRewards` pot for that era).

### Likelihood Explanation
Medium. It requires the `use_dap_payout` transfer path to be active (`DisableMintingGuard` set for the era, i.e. post-migration to the transfer-based reward pot design) and a transfer failure condition — most plausibly a nominator/validator payout amount rounding below `ExistentialDeposit` for an account that no longer exists (fully unbonded/reaped), or the era's `StakerRewards` pot being insufficiently funded relative to computed entitlements due to rounding accumulation across pages/pots. Given `payout_stakers_by_page` is fully permissionless and can be called by anyone for anyone's validator/era/page, the attacker cost is a single ordinary extrinsic; no governance or validator control is needed.

### Recommendation
Propagate transfer failures from `make_payout_from_provider` out of `payout_from_provider`/`do_payout_stakers_by_page` as a `DispatchError` (mirroring the fix already applied to `pallet-broker::do_claim_revenue` in `prdoc/pr_13040.prdoc`), so the whole extrinsic (including the `set_rewards_as_claimed` storage write) reverts atomically when any recipient's payment cannot be completed. Alternatively, defer marking the page as claimed until all transfers for that page have succeeded, or provide a supported "un-claim" path when a transfer fails so genuinely entitled rewards remain claimable.

### Proof of Concept
Not executed in this session — no sandbox/compute environment was available to run a FRAME test. The finding is based on direct code inspection of the exact lines cited above:
- `Eras::<T>::set_rewards_as_claimed(era, &stash, page)` executed unconditionally before payout, at `substrate/frame/staking-async/src/pallet/impls.rs:386`.
- `make_payout_from_provider`'s transfer failure being swallowed (`log!(error, ...); return None;`) without propagating a `DispatchError`, at `substrate/frame/staking-async/src/pallet/impls.rs:602-616`.
- No un-claim / rollback mechanism exists for `Eras::set_rewards_as_claimed` (confirmed via `grep_search` — only forward-marking usages found).

A concrete reproduction should be built analogous to the existing `claim_revenue_reverts_when_pot_cannot_pay` test in `substrate/frame/broker/src/tests.rs:3364` (which validates the *fixed* behavior in pallet-broker): set up an era with `DisableMintingGuard` active for `use_dap_payout`, drain/underfund the `RewardPot::Era(era, RewardKind::StakerRewards)` account (or arrange a nominator's per-page reward to round below `ExistentialDeposit` for a reaped/non-existent account), call `payout_stakers_by_page`, and assert that (a) the extrinsic returns `Ok`, (b) no balance change occurred for the affected recipient, and (c) a subsequent claim attempt for the same `(era, stash, page)` fails with `Error::AlreadyClaimed`, proving the entitlement was permanently lost. This test was not run due to lack of a runtime/compute environment in this session; it is provided as the exact reproduction path a Devin session with repo access should execute to confirm the PoC deterministically.

### Citations

**File:** substrate/frame/staking-async/src/pallet/impls.rs (L381-391)
```rust
		if Eras::<T>::is_rewards_claimed(era, &stash, page) {
			return Err(Error::<T>::AlreadyClaimed
				.with_weight(T::WeightInfo::payout_stakers_alive_staked(0)));
		}

		Eras::<T>::set_rewards_as_claimed(era, &stash, page);

		let exposure = Eras::<T>::get_paged_exposure(era, &stash, page).ok_or_else(|| {
			Error::<T>::InvalidEraToReward
				.with_weight(T::WeightInfo::payout_stakers_alive_staked(0))
		})?;
```

**File:** substrate/frame/staking-async/src/pallet/impls.rs (L451-473)
```rust
		// Determine whether to use dap payout or legacy path.
		let use_dap_payout =
			DisableMintingGuard::<T>::get().is_some_and(|guard_era| era >= guard_era);

		let nominator_payout_count: u32 = if use_dap_payout {
			Self::payout_from_provider(
				era,
				&stash,
				validator_staker_payout_for_page,
				&exposure,
				overview_own,
				reward_split.nominator_payout,
			)
		} else {
			Self::payout_legacy_mint(
				era,
				&stash,
				validator_staker_payout_for_page,
				&exposure,
				overview_own,
				reward_split.nominator_payout,
			)
		};
```

**File:** substrate/frame/staking-async/src/pallet/impls.rs (L480-516)
```rust
	/// Payout stakers from an era reward pot (transfer-based, no minting).
	fn payout_from_provider(
		era: EraIndex,
		stash: &T::AccountId,
		validator_payout: BalanceOf<T>,
		exposure: &crate::PagedExposure<T::AccountId, BalanceOf<T>>,
		overview_own: BalanceOf<T>,
		total_nominator_payout: BalanceOf<T>,
	) -> u32 {
		let mut nominator_payout_count: u32 = 0;

		if let Some((amount, dest)) = Self::make_payout_from_provider(era, stash, validator_payout)
		{
			Self::deposit_event(Event::<T>::Rewarded { stash: stash.clone(), dest, amount });
		}

		let total_nominator_stake = exposure.total().saturating_sub(overview_own);
		for nominator in exposure.others().iter() {
			let nominator_exposure_part =
				Perbill::from_rational(nominator.value, total_nominator_stake);
			let nominator_reward: BalanceOf<T> =
				nominator_exposure_part.mul_floor(total_nominator_payout);

			if let Some((amount, dest)) =
				Self::make_payout_from_provider(era, &nominator.who, nominator_reward)
			{
				nominator_payout_count.saturating_inc();
				Self::deposit_event(Event::<T>::Rewarded {
					stash: nominator.who.clone(),
					dest,
					amount,
				});
			}
		}

		nominator_payout_count
	}
```

**File:** substrate/frame/staking-async/src/pallet/impls.rs (L577-616)
```rust
	/// Make a payment to a staker from an era reward pot (transfer, not mint).
	fn make_payout_from_provider(
		era: EraIndex,
		stash: &T::AccountId,
		amount: BalanceOf<T>,
	) -> Option<(BalanceOf<T>, RewardDestination<T::AccountId>)> {
		if amount.is_zero() {
			return None;
		}

		let dest = match Self::payee(Stash(stash.clone())) {
			Some(d) => d,
			None => {
				Self::deposit_event(Event::<T>::Unexpected(UnexpectedKind::MissingPayee {
					era,
					stash: stash.clone(),
				}));
				return None;
			},
		};

		let payout_account = Self::payout_account_for_dest(stash, &dest)?;

		let staker_rewards_pot =
			T::RewardPots::pot_account(RewardPot::Era(era, RewardKind::StakerRewards));
		if let Err(e) = T::Currency::transfer(
			&staker_rewards_pot,
			&payout_account,
			amount,
			Preservation::Expendable,
		) {
			log!(
				error,
				"Failed to transfer reward from pot for era {:?}, stash {:?}: {:?}",
				era,
				stash,
				e
			);
			return None;
		}
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
