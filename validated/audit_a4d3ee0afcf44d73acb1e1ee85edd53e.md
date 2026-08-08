### Title
Vote accounts can flash-fund their balance to pass the VAT epoch-eligibility snapshot, then immediately withdraw — bypassing the Alpenglow Validator Admission Ticket balance gate ([File: runtime/src/bank.rs], [vote/src/vote_account.rs], [programs/vote/src/vote_state/mod.rs])

### Summary
The reported bug class is a temporary balance top-up ("flash loan") used to pass a point-in-time eligibility check that gates access to a privileged pool, followed by an immediate reversal of the balance once the check has been satisfied. Agave's Alpenglow "Validator Admission Ticket" (VAT) mechanism has the same structural weakness: vote-account eligibility for the epoch's stake/reward set is decided by a single balance snapshot taken at the epoch boundary, and the vote program's `Withdraw` instruction has no lock-up, so the balance used to pass the gate can be withdrawn again immediately after the snapshot is taken.

### Finding Description
Each epoch boundary, `Bank::compute_new_epoch_caches_and_rewards` reads the *current* stakes-cache vote-account balances and filters them with `clone_and_filter_for_vat`, which only checks `vote_account.lamports() >= minimum_vote_account_balance`: [1](#0-0) 

This filtered set becomes the `filtered_distribution_vote_accounts` used both for reward distribution and for the epoch's `EpochStakes` snapshot: [2](#0-1) 

The minimum balance itself is only intended to guarantee funds for *future* per-epoch burns (`DEFAULT_VAT_TO_BURN_PER_EPOCH * num_epochs + rent_exempt_reserve`), not to require the funds be held for any minimum duration: [3](#0-2) 

Once the epoch stakes snapshot and the one-time VAT burn are applied at the boundary (`update_epoch_stakes` → `maybe_burn_vat_from_staked_accounts`, executed as part of bank state transition, not as a user transaction): [4](#0-3) 

the vote account's authorized withdrawer can immediately withdraw the balance back out in the very first transaction of the new epoch, because `withdraw()` in the vote program only enforces a rent-exempt floor (plus any pending delegator rewards) — there is no time-lock or minimum holding period tied to VAT eligibility: [5](#0-4) 

This is the same primitive as the NFT-flashloan report: transfer funds in, pass a snapshot-based gate, transfer funds back out — because the gate checks a balance at one instant with no lock, rather than a sustained commitment.

### Impact Explanation
`clone_and_filter_for_vat` is also responsible for truncating the eligible vote-account set to `MAX_ALPENGLOW_VOTE_ACCOUNTS` by stake, after removing accounts below the balance floor: [6](#0-5) 

An operator who does not actually intend to sustain the VAT balance requirement can top up their vote account just before the epoch-boundary slot, get admitted into (or avoid being excluded from) the epoch's stake/reward-eligible set — potentially displacing a genuinely, continuously funded validator from the bounded top-`MAX_ALPENGLOW_VOTE_ACCOUNTS` list — receive that epoch's commission/reward attribution, and then withdraw the capital again once included, repeating every epoch. This is a misattribution of epoch-stake/reward-eligibility state: a validator is credited as VAT-compliant, and consumes a slot in a hard-capped admission list, without maintaining the actual capital commitment the mechanism is designed to enforce.

### Likelihood Explanation
The single balance check is deterministic, uses the exact bank state at the parent slot of the epoch boundary, and the withdraw path has no cooldown, so the top-up/pass/withdraw sequence is reliably reproducible every epoch by any account holder who controls a vote account's authorized withdrawer key — no privileged validator/consensus role is required beyond owning the vote account.

### Recommendation
Do not gate VAT eligibility on an instantaneous balance snapshot. Consider requiring the qualifying balance to have been held continuously for some minimum window prior to the epoch boundary (e.g., tracked via a running minimum-balance-since-last-checkpoint, analogous to the report's suggestion of locking the asset for at least one block), or require VAT top-ups to go through a delayed-activation mechanism similar to stake warm-up, so momentary balance inflation cannot satisfy `clone_and_filter_for_vat`.

### Proof of Concept
1. Attacker controls a vote account `V` whose current balance is below `minimum_vote_account_balance_for_vat()`.
2. In the last slot of epoch `N`, attacker's withdraw/staker authority transfers lamports into `V` so its balance now exceeds `minimum_vote_account_balance_for_vat()`.
3. At the epoch boundary (start of epoch `N+1`), `Bank::process_new_epoch` → `compute_new_epoch_caches_and_rewards` snapshots `V`'s inflated balance, `clone_and_filter_for_vat` admits `V` into `filtered_distribution_vote_accounts`/`EpochStakes` for epoch `N+1`, and `maybe_burn_vat_from_staked_accounts` burns exactly one epoch's VAT fee from `V`.
4. In the first transaction of epoch `N+1`, the authorized withdrawer submits `VoteInstruction::Withdraw` to pull the remaining excess lamports back out of `V`, down to just above the rent-exempt minimum, per `withdraw()`'s only enforced floor.
5. `V` is now counted as VAT-eligible / consensus-admitted for the whole of epoch `N+1` and receives associated reward/commission attribution, despite holding only rent-exempt-minimum lamports for the entire rest of the epoch. The sequence can be repeated every epoch boundary.

### Citations

**File:** vote/src/vote_account.rs (L220-230)
```rust
        for (pubkey, (stake, vote_account)) in self.vote_accounts.iter() {
            let has_bls = vote_account
                .vote_state_view()
                .bls_pubkey_compressed()
                .is_some();
            let has_stake = *stake != 0u64;
            let has_balance = vote_account.lamports() >= minimum_vote_account_balance;

            if !has_bls || !has_stake || !has_balance {
                continue;
            }
```

**File:** vote/src/vote_account.rs (L233-245)
```rust

        let valid_len = entries_to_sort.len();
        if entries_to_sort.len() > max_vote_accounts {
            // Find the cutoff stake using partial sort (more efficient than full sort).
            let (_, cutoff_entry, _) =
                entries_to_sort.select_nth_unstable_by(max_vote_accounts, |a, b| b.2.cmp(&a.2));
            let floor_stake = cutoff_entry.2;

            // Per SIMD 357, we remove all vote accounts with stake smaller or equal to
            // the first truncated one.
            entries_to_sort.retain(|(_, _, stake)| *stake > floor_stake);
        }

```

**File:** runtime/src/bank.rs (L1781-1792)
```rust
        // Apply stake rewards and commission using the VAT-filtered distribution
        // vote-account snapshot.
        let filtered_distribution_vote_accounts = unfiltered_distribution_vote_accounts
            .clone_and_filter_for_vat(
                MAX_ALPENGLOW_VOTE_ACCOUNTS,
                self.minimum_vote_account_balance_for_vat(),
            );
        if AlpenglowEpochType::is_alpenglow_or_migration_epoch(self, rewarded_epoch) {
            reward_epoch_delegated_stakes.set(self, &filtered_distribution_vote_accounts);
        }
        let cached_vote_accounts =
            self.get_cached_vote_accounts(rewarded_epoch, &filtered_distribution_vote_accounts);
```

**File:** runtime/src/bank.rs (L2608-2626)
```rust
            // At the epoch boundary, `compute_new_epoch_caches_and_rewards`
            // has already produced the VAT-filtered vote-account snapshot;
            // reuse it here instead of re-cloning and re-filtering the
            // `stakes_cache`. Other callers (same-epoch refresh, warps)
            // fall back to `get_top_epoch_stakes`.
            let stakes = match prefiltered_distribution_vote_accounts {
                Some(prefiltered) => Stakes::new(prefiltered, self.epoch()),
                None => self.get_top_epoch_stakes(),
            };
            let stakes = SerdeStakesToStakeFormat::from(stakes);
            let new_epoch_stakes = VersionedEpochStakes::new(stakes, leader_schedule_epoch);
            info!(
                "new epoch stakes, epoch: {}, total_stake: {}",
                leader_schedule_epoch,
                new_epoch_stakes.total_stake(),
            );

            self.maybe_burn_vat_from_staked_accounts(&new_epoch_stakes);

```

**File:** runtime/src/genesis_utils.rs (L58-63)
```rust
// Default minimum vote account balance used by tests/genesis helpers. This is
// conservative once shorter slot-time regimes lower the live bank VAT burn.
pub fn minimum_vote_account_balance_for_vat(num_epochs: Epoch) -> u64 {
    DEFAULT_VAT_TO_BURN_PER_EPOCH * num_epochs
        + Rent::default().minimum_balance(VoteStateV4::size_of())
}
```

**File:** programs/vote/src/vote_state/mod.rs (L1079-1122)
```rust
    let remaining_balance = vote_account
        .get_lamports()
        .checked_sub(lamports)
        .ok_or(InstructionError::InsufficientFunds)?;

    // Always zero until SIMD-0123 is activated.
    let pending_delegator_rewards = vote_state.pending_delegator_rewards();

    if remaining_balance == 0 {
        // SIMD-0123: vote account cannot be closed if
        // pending_delegator_rewards > 0.
        if pending_delegator_rewards > 0 {
            return Err(InstructionError::InsufficientFunds);
        }

        let reject_active_vote_account_close = vote_state
            .epoch_credits()
            .last()
            .map(|(last_epoch_with_credits, _, _)| {
                let current_epoch = clock.epoch;
                // if current_epoch - last_epoch_with_credits < 2 then the validator has received credits
                // either in the current epoch or the previous epoch. If it's >= 2 then it has been at least
                // one full epoch since the validator has received credits.
                current_epoch.saturating_sub(*last_epoch_with_credits) < 2
            })
            .unwrap_or(false);

        if reject_active_vote_account_close {
            return Err(VoteError::ActiveVoteAccountClose.into());
        } else {
            // Deinitialize upon zero-balance
            VoteStateHandler::deinitialize_vote_account_state(&mut vote_account, target_version)?;
        }
    } else {
        // SIMD-0123: withdrawable balance when pending_delegator_rewards > 0
        // is lamports - pending_delegator_rewards - rent_exempt_minimum.
        let min_rent_exempt_balance = rent_sysvar.minimum_balance(vote_account.get_data().len());
        let min_balance = min_rent_exempt_balance
            .checked_add(pending_delegator_rewards)
            .ok_or(InstructionError::ArithmeticOverflow)?;
        if remaining_balance < min_balance {
            return Err(InstructionError::InsufficientFunds);
        }
    }
```
