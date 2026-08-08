## #Title
Stake-delegation accounting recomputes `old_stake` with the wrong warmup/cooldown formula, causing a `checked_sub().expect()` panic (validator crash) analogous to the GaugeController delta-less subtraction bug - ([File: runtime/src/stakes.rs])

### Summary
The GaugeController report's root cause is a weight-update formula that subtracts a *previous* contribution recomputed with *current* parameters instead of tracking the actual delta, causing an underflow. Agave's `Stakes::upsert_stake_delegation` / `sub_delegated_stake` / `VoteAccounts::sub_stake` have the analogous pattern: when a stake account is modified, the "old" contribution that must be subtracted from the cached `delegated_stakes`/vote-account stake totals is *recomputed on the fly* using the currently active warmup/cooldown math flag rather than the flag that was in effect when that stake was originally added to the cache. If the flag changes between the two calls (e.g., the `upgrade_bpf_stake_program_to_v5_1` feature activates mid-epoch), the recomputed `old_stake` can differ from the value actually stored in the aggregate, and the subsequent `checked_sub(...).expect(...)` panics instead of silently producing wrong results — but the underlying defect (using a re-derived value instead of the true previously-recorded delta) is the same class of bug as the report.

### Finding Description
`Stakes::upsert_stake_delegation` computes both the new and old effective stake for a delegation using `delegation_effective_stake`, which dispatches to `stake_v2` (fixed-point math) or the legacy `stake()` formula depending on the boolean `use_fixed_point_stake_math`: [1](#0-0) 

Note that `old_stake` is derived by calling `delegation_effective_stake` again with the *current* `use_fixed_point_stake_math` argument, not the value that was actually used the last time this delegation's stake was added to `delegated_stakes`/`vote_accounts`. When `voter_pubkey != old_voter_pubkey || stake != old_stake`, this recomputed `old_stake` is fed into `sub_delegated_stake` and `vote_accounts.sub_stake`: [2](#0-1) [3](#0-2) 

Both subtraction helpers use `checked_sub(...).expect(...)`, which will panic the validator process if the recomputed `old_stake` does not match what was actually accumulated in the map.

The math flag itself is derived per-call from the bank's live feature set: [4](#0-3) 

`Bank::use_fixed_point_stake_math()` reads `self.feature_set.snapshot().upgrade_bpf_stake_program_to_v5_1` at call time, so if a stake account's delegation was originally added to the `Stakes` cache (via `upsert_stake_delegation`/`check_and_store`) while the feature was inactive, and the feature activates before the account is later modified again within the *same* `Stakes.epoch` (delegated stake totals are only rebuilt wholesale at epoch boundaries via `refresh_delegated_stakes`/`calculate_activated_stake`), the second call recomputes `old_stake` with the new math and can diverge from the amount that is actually present in `delegated_stakes[voter_pubkey]` / `vote_accounts` stake, exactly mirroring the GaugeController flaw of "subtracting a freshly recomputed contribution instead of tracking the real delta."

### Impact Explanation
If the recomputed `old_stake` exceeds the true residual in the map, `checked_sub(...).expect("subtraction value exceeds delegated stake")` (or the vote-account/node-stake equivalents) panics. Because `upsert_stake_delegation` is invoked from the generic account-store path (`check_and_store`) that every stake-program instruction executed by unprivileged users passes through (delegate, split, merge, deactivate, withdraw, redelegate, set-lockup, etc.), a routine user stake operation processed in the epoch where this feature activation window opens can crash any validator that processes it, which — since features activate cluster-wide at a specific slot — can hit many/most validators near-simultaneously and produce a consensus-affecting halt rather than a single-node crash.

### Likelihood Explanation
This requires a specific, narrow timing window: a feature toggling `use_fixed_point_stake_math` (or any future flag routed through `delegation_effective_stake`) must activate strictly inside an epoch (not at the epoch boundary) between two stake-account mutations touching the same delegation, and the old/new formulas must produce different effective-stake values for the same delegation state (which is plausible given `stake_v2` uses different, fixed-point rounding vs. the legacy floating-point `stake()`). This is a real, unprivileged-user-triggerable path (any stake instruction), but its likelihood depends on feature-activation timing rather than being trivially reproducible on demand, which is why it is flagged as a real but conditional finding rather than a certain one.

### Recommendation
Do not recompute the "old" contribution to `delegated_stakes`/`vote_accounts` using the *current* math flag. Instead, store the effective stake value that was actually recorded for a delegation the last time it was inserted (e.g., alongside the `StakeAccount` in the map, or as part of the cached entry), and use that stored value directly when subtracting in `upsert_stake_delegation`/`remove_stake_delegation`, so the subtraction always uses the true previously-applied delta rather than a value re-derived under potentially different warmup/cooldown math.

### Proof of Concept
1. Start a bank at epoch E with `upgrade_bpf_stake_program_to_v5_1` inactive; a user delegates stake, causing `upsert_stake_delegation` to add `old_stake = delegation.stake(...)` (legacy formula) to `delegated_stakes`/`vote_accounts`.
2. Within the same epoch E (before the next `activate_epoch`/`refresh_delegated_stakes` call), the feature activates at a later slot.
3. The same user issues another stake instruction touching the same delegation (e.g., a partial deactivate/merge), triggering `upsert_stake_delegation` again; `old_stake` is now recomputed with `stake_v2` (fixed-point formula) instead of the legacy formula used when it was first added.
4. If `stake_v2(...)` for that delegation state yields a value greater than what is actually stored in `delegated_stakes[voter_pubkey]`, `sub_delegated_stake`'s `checked_sub(...).expect("subtraction value exceeds delegated stake")` panics, crashing the validator that processes this transaction — reproducing, in Rust's checked-panic form, the same "stale recomputation instead of real delta" defect described in the GaugeController report.

### Citations

**File:** runtime/src/stakes.rs (L562-576)
```rust
    fn sub_delegated_stake(&mut self, voter_pubkey: &Pubkey, stake: u64) {
        if stake == 0 {
            return;
        }
        let current_stake = self
            .delegated_stakes
            .get_mut(voter_pubkey)
            .expect("subtraction from missing delegated stake");
        *current_stake = current_stake
            .checked_sub(stake)
            .expect("subtraction value exceeds delegated stake");
        if *current_stake == 0 {
            self.delegated_stakes.remove(voter_pubkey);
        }
    }
```

**File:** runtime/src/stakes.rs (L620-659)
```rust
    fn upsert_stake_delegation(
        &mut self,
        stake_pubkey: Pubkey,
        stake_account: StakeAccount,
        new_rate_activation_epoch: Option<Epoch>,
        use_fixed_point_stake_math: bool,
    ) {
        debug_assert_ne!(stake_account.lamports(), 0u64);
        let delegation = stake_account.delegation();
        let voter_pubkey = delegation.voter_pubkey;
        let stake = delegation_effective_stake(
            delegation,
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
            use_fixed_point_stake_math,
        );
        match self.stake_delegations.insert(stake_pubkey, stake_account) {
            None => {
                self.add_delegated_stake(voter_pubkey, stake);
                self.vote_accounts.add_stake(&voter_pubkey, stake);
            }
            Some(old_stake_account) => {
                let old_delegation = old_stake_account.delegation();
                let old_voter_pubkey = old_delegation.voter_pubkey;
                let old_stake = delegation_effective_stake(
                    old_delegation,
                    self.epoch,
                    &self.stake_history,
                    new_rate_activation_epoch,
                    use_fixed_point_stake_math,
                );
                if voter_pubkey != old_voter_pubkey || stake != old_stake {
                    self.sub_delegated_stake(&old_voter_pubkey, old_stake);
                    self.add_delegated_stake(voter_pubkey, stake);
                    self.vote_accounts.sub_stake(&old_voter_pubkey, old_stake);
                    self.vote_accounts.add_stake(&voter_pubkey, stake);
                }
            }
        }
```

**File:** vote/src/vote_account.rs (L359-368)
```rust
    pub fn sub_stake(&mut self, pubkey: &Pubkey, delta: u64) {
        let vote_accounts = Arc::make_mut(&mut self.vote_accounts);
        if let Some((stake, vote_account)) = vote_accounts.get_mut(pubkey) {
            *stake = stake
                .checked_sub(delta)
                .expect("subtraction value exceeds account's stake");
            let vote_account = vote_account.clone();
            self.sub_node_stake(delta, &vote_account);
        }
    }
```

**File:** runtime/src/stake_delegation.rs (L9-23)
```rust
#[inline]
pub(crate) fn delegation_effective_stake<T: StakeHistoryGetEntry>(
    delegation: &Delegation,
    epoch: Epoch,
    history: &T,
    new_rate_activation_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
) -> u64 {
    if use_fixed_point_stake_math {
        delegation.stake_v2(epoch, history, new_rate_activation_epoch)
    } else {
        #[allow(deprecated)]
        delegation.stake(epoch, history, new_rate_activation_epoch)
    }
}
```
