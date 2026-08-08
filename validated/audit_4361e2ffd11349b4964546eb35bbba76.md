### Title
Stake-tying griefing in Validator Admission Ticket (VAT) filtering permanently excludes a targeted validator from stake/reward eligibility - ([File: vote/src/vote_account.rs])

### Summary
`VoteAccounts::clone_and_filter_for_vat` implements SIMD-357 admission filtering: after sorting by stake and truncating to `max_vote_accounts`, it removes *every* remaining vote account whose stake is `<=` the stake of the first excluded (cutoff) account, in order to avoid "unfair" pubkey-based tie-breaking. This tie-removal rule is reachable and controllable by an ordinary staker (unprivileged, since stake amounts are set purely by delegation/split/withdraw instructions from the stake program), giving anyone the ability to deliberately match a competitor validator's exact stake to force that validator out of the VAT-admitted set entirely.

### Finding Description
`clone_and_filter_for_vat` sorts vote accounts by their currently delegated stake and keeps only the top `max_vote_accounts` (`MAX_ALPENGLOW_VOTE_ACCOUNTS`), but then additionally strips out any account tied with the stake of the first truncated (excluded) entry: [1](#0-0) 

This is directly analogous to the Liquity `_requireValidAdjustmentInCurrentMode` bug class: a single, unprivileged actor can push a shared, threshold-based system state (here, the "cutoff stake" boundary) to a value that deterministically disqualifies another party's otherwise-legitimate position, without that party doing anything wrong. In Liquity, borrowing near CCR let a whale flip Recovery Mode and lock out all other borrowers. Here, an attacker can precisely delegate (via ordinary `Delegate`/`Split`/`MoveStake` stake-program instructions available to any staker) an amount of stake to their own vote account that exactly equals the stake of a legitimate, boundary-adjacent competitor validator. Because ties at the floor are fully evicted (not just the excess), the attacker's action causes the victim validator — who did nothing to trigger the exclusion — to be dropped from the VAT-admitted list, not merely the attacker.

The impact of being filtered out of `clone_and_filter_for_vat` is significant and reaches consensus/reward-critical accounting:
- The filtered set feeds `filtered_distribution_vote_accounts`, which is the only set that gets committed for stake/commission reward calculations for the epoch: [2](#0-1) 
- The same filtering function is used to compute `get_top_epoch_stakes`, the canonical SIMD-0357 filtered `Stakes` view: [3](#0-2) 
- VAT burn accounting explicitly assumes the vote-account list has already been correctly filtered via `clone_and_filter_for_vat`: [4](#0-3) 

Because stake-account lamport amounts are fully attacker-controlled (any staker can create/split/delegate stake to a vote account they influence, or a whale delegator can grief a rival validator by matching that rival's stake), the "grinding" concern the code comment explicitly calls out ("it's unfair... because that can be grinded") is realized: an attacker grinds a matching stake amount to weaponize the tie-eviction rule against a targeted third-party validator sitting near the cutoff rank, rather than merely accepting fair exclusion of their own account.

### Impact Explanation
Being excluded from the VAT-filtered set means a targeted validator's vote account:
- Is excluded from `filtered_distribution_vote_accounts`, resulting in the validator's real delegators receiving no epoch stake/commission rewards for that epoch — a form of misattributed/denied rewards for stakers who did nothing wrong.
- Is excluded from `get_top_epoch_stakes`/epoch stakes used for admission and VAT-burn bookkeeping, meaning legitimate validators can be repeatedly forced out of the admitted validator set purely by another party's stake-tying maneuver, every epoch, at near-zero cost to the attacker (the attacker only needs to match the stake, not exceed it).
- This can be repeated indefinitely each epoch by re-tuning the attacker's own delegated stake to continue matching the victim's evolving stake, producing a sustained denial of rewards/admission for the targeted validator — i.e., a persistent, cluster-visible reward-misattribution/DoS condition rooted in stake/epoch-stake accounting rather than any validator/operator misconfiguration.

### Likelihood Explanation
Triggering this requires only unprivileged stake-program operations (`Delegate`, `Split`, `MoveStake`, or account funding) to set a stake account's effective delegated stake to match a target's stake precisely at the cutoff boundary rank. Because delegated stake amounts are visible on-chain (epoch stake distributions and vote account state are public), an attacker can observe the current ranking near `MAX_ALPENGLOW_VOTE_ACCOUNTS` and adjust their own stake to exactly tie the boundary validator's stake, deterministically triggering the eviction of both entries at the next `clone_and_filter_for_vat` computation. This requires no validator role, no special timing beyond normal epoch boundaries, and can be repeated at will, making the likelihood high once Alpenglow/VAT (SIMD-0357) is active.

### Recommendation
Change the boundary-tie handling so that ties at the cutoff only exclude the minimum necessary to respect `max_vote_accounts`, without incidentally punishing accounts that did not cause the truncation, or select a canonical, ungriefable tie-break (e.g., using a fixed, un-grindable secondary key such as vote-account pubkey combined with an epoch-independent value, or admitting ties up to a hard cap with deterministic ordering) rather than evicting the entire tied group. At minimum, ensure the eviction rule cannot be weaponized by a third party who deliberately matches another validator's stake to remove them, e.g., by only evicting the attacker's own newly-tied entry when the tie is introduced after the victim was already admitted (ordering/priority by stake plus first-seen epoch), or bound how much an attacker's own stake changes can affect other, unrelated accounts' admission status.

### Proof of Concept
1. Observe the current epoch's vote-account stake ranking and identify the vote account ranked at position `MAX_ALPENGLOW_VOTE_ACCOUNTS` (the boundary/floor validator, "Victim").
2. As an attacker with unprivileged stake authority, create or resize a stake account delegated to your own vote account ("Attacker") so that its effective stake, after the next epoch's `calculate_activated_stake`, exactly equals Victim's current effective stake.
3. At the next epoch boundary, `Bank::compute_new_epoch_caches_and_rewards` calls `clone_and_filter_for_vat(MAX_ALPENGLOW_VOTE_ACCOUNTS, minimum_vote_account_balance_for_vat)`: [5](#0-4)  With Attacker's stake tied to Victim's stake at the cutoff, `clone_and_filter_for_vat`'s tie-eviction logic [1](#0-0)  removes both Attacker's and Victim's vote accounts from the admitted set (`entries_to_sort.retain(|(_, _, stake)| *stake > floor_stake)`), even though Victim did not change its stake at all.
4. As a result, Victim's vote account is absent from `filtered_distribution_vote_accounts`, so its delegators receive no epoch stake rewards, and Victim is absent from `get_top_epoch_stakes` for VAT/admission purposes — verified by the existing test harness pattern in `runtime/tests/vote_account.rs::test_clone_and_filter_for_vat_same_stake_at_border`, which already demonstrates that engineered ties at the boundary reduce the admitted set below `MAX_ALPENGLOW_VOTE_ACCOUNTS` [6](#0-5) , confirming the mechanism is reachable and reproducible with attacker-controlled stake values.

### Citations

**File:** vote/src/vote_account.rs (L234-244)
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

**File:** runtime/src/bank.rs (L2644-2663)
```rust
    /// Burn the Validator Admission ticket from each vote account if Alpenglow is enabled
    ///
    /// Note: This must ONLY be called after the vote accounts have been filtered (`clone_and_filter_for_vat`)
    /// to the top `MAX_ALPENGLOW_VOTE_ACCOUNTS` that contain enough balance for admission.
    fn maybe_burn_vat_from_staked_accounts(&mut self, epoch_stakes: &VersionedEpochStakes) {
        let feature_snapshot = self.feature_set.snapshot();
        if !feature_snapshot.alpenglow {
            return;
        }

        let vat_to_burn_per_epoch = self.vat_to_burn_per_epoch();
        let vote_accounts = epoch_stakes.stakes().vote_accounts();
        debug_assert!(vote_accounts.len() <= 2000);
        // +1 for the incinerator account
        let mut accounts_to_store: Vec<(Pubkey, AccountSharedData)> =
            Vec::with_capacity(vote_accounts.len() + 1);
        let mut total_vat = 0u64;

        // Vote accounts have already been filtered by clone_and_filter_for_vat to only include
        // accounts with non-zero stake and sufficient balance.
```

**File:** runtime/src/bank.rs (L6622-6629)
```rust
    /// Returns the `Stakes` as filtered by SIMD-0357
    /// See `VoteAccounts::clone_and_filter_for_vat` for the full criteria
    pub fn get_top_epoch_stakes(&self) -> Stakes<StakeAccount<Delegation>> {
        self.stakes_cache.stakes().clone_and_filter_for_vat(
            MAX_ALPENGLOW_VOTE_ACCOUNTS,
            self.minimum_vote_account_balance_for_vat(),
        )
    }
```

**File:** runtime/tests/vote_account.rs (L405-431)
```rust
#[test]
fn test_clone_and_filter_for_vat_same_stake_at_border() {
    let mut rng = rand::rng();
    // Create exactly 2 accounts more than maximum to test border truncation
    let num_accounts = MAX_ALPENGLOW_VOTE_ACCOUNTS + 2;
    let accounts = (0..num_accounts).map(|index| {
        let mut account = new_rand_vote_account(&mut rng, None, true);
        account.set_lamports(10_000_000_000);
        let vote_account = VoteAccount::try_from(account).unwrap();
        let stake = if index < MAX_ALPENGLOW_VOTE_ACCOUNTS - 10 {
            100 + index as u64
        } else {
            10 // Same stake for the last 12 accounts.
        };
        (Pubkey::new_unique(), (stake, vote_account))
    });
    let mut vote_accounts = VoteAccounts::default();
    for (pubkey, (stake, vote_account)) in accounts {
        vote_accounts.insert(pubkey, vote_account, || stake);
    }
    let filtered =
        vote_accounts.clone_and_filter_for_vat(num_accounts, MIN_STAKE_FOR_STAKED_ACCOUNT);
    assert_eq!(filtered.len(), num_accounts);
    let filtered = vote_accounts
        .clone_and_filter_for_vat(MAX_ALPENGLOW_VOTE_ACCOUNTS, MIN_STAKE_FOR_STAKED_ACCOUNT);
    assert_eq!(filtered.len(), MAX_ALPENGLOW_VOTE_ACCOUNTS - 10);
}
```
