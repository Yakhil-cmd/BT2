#No Vulnerability found for this question.

The dispatch logic that selects between `Delegation::stake_activating_and_deactivating` and `Delegation::stake_activating_and_deactivating_v2` lives in [1](#0-0)  and is driven by a single bank-wide snapshot of the `upgrade_bpf_stake_program_to_v5_1` feature flag, read once per epoch-boundary computation via `Bank::use_fixed_point_stake_math` [2](#0-1) . This flag is applied uniformly to every stake delegation processed in `Stakes::calculate_activated_stake` and `refresh_vote_accounts` within the same call [3](#0-2) [4](#0-3) , so an attacker cannot cause the two math modes to be applied inconsistently to different delegations for the same epoch — every delegation in a given epoch's accounting uses the same formula, decided by cluster-wide feature activation, not by attacker-controlled timing of individual delegate/deactivate instructions.

The actual arithmetic of `stake_activating_and_deactivating` and `stake_activating_and_deactivating_v2` is implemented in the external `solana-stake-interface` crate, which is a dependency pulled in via Cargo (confirmed as an external package reference, not in-repo source) [5](#0-4) , and per the SECURITY.md scope rules, dependency-crate internals are explicitly out of scope for this audit. Since the in-repo dispatch code enforces a single consistent formula choice across all delegations within an epoch (no per-account or per-transaction attacker control over which formula is used), and the actual warmup/cooldown math is out-of-scope dependency code, there is no reachable, in-scope attacker path in this repository that would produce the claimed divergence or supply inflation.

### Citations

**File:** runtime/src/stake_delegation.rs (L26-39)
```rust
pub(crate) fn delegation_activation_status<T: StakeHistoryGetEntry>(
    delegation: &Delegation,
    epoch: Epoch,
    history: &T,
    new_rate_activation_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
) -> StakeActivationStatus {
    if use_fixed_point_stake_math {
        delegation.stake_activating_and_deactivating_v2(epoch, history, new_rate_activation_epoch)
    } else {
        #[allow(deprecated)]
        delegation.stake_activating_and_deactivating(epoch, history, new_rate_activation_epoch)
    }
}
```

**File:** runtime/src/bank.rs (L1717-1721)
```rust
    fn use_fixed_point_stake_math(&self) -> bool {
        self.feature_set
            .snapshot()
            .upgrade_bpf_stake_program_to_v5_1
    }
```

**File:** runtime/src/stakes.rs (L434-465)
```rust
    pub(crate) fn calculate_activated_stake(
        &self,
        next_epoch: Epoch,
        thread_pool: &ThreadPool,
        new_rate_activation_epoch: Option<Epoch>,
        stake_delegations: &[(&Pubkey, &StakeAccount)],
        use_fixed_point_stake_math: bool,
    ) -> (
        StakeHistory,
        VoteAccounts,
        DelegatedStakes,
        RewardEpochDelegatedStakes,
    ) {
        // Wrap up the prev epoch by adding new stake history entry for the
        // prev epoch.
        let (stake_history_entry, effective_delegated_stakes) = thread_pool.install(|| {
            stake_delegations
                .par_iter()
                .fold(
                    || (StakeActivationStatus::default(), HashMap::default()),
                    |(acc, mut delegated_stakes), (_stake_pubkey, stake_account)| {
                        let delegation = stake_account.delegation();
                        let activation_status = delegation_activation_status(
                            delegation,
                            self.epoch,
                            &self.stake_history,
                            new_rate_activation_epoch,
                            use_fixed_point_stake_math,
                        );
                        *delegated_stakes.entry(delegation.voter_pubkey).or_default() +=
                            activation_status.effective;
                        (acc + activation_status, delegated_stakes)
```

**File:** runtime/src/stakes.rs (L756-795)
```rust
fn refresh_vote_accounts(
    thread_pool: &ThreadPool,
    epoch: Epoch,
    vote_accounts: &VoteAccounts,
    stake_delegations: &[(&Pubkey, &StakeAccount)],
    stake_history: &StakeHistory,
    new_rate_activation_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
) -> (VoteAccounts, DelegatedStakes) {
    fn merge(mut stakes: DelegatedStakes, other: DelegatedStakes) -> DelegatedStakes {
        if stakes.len() < other.len() {
            return merge(other, stakes);
        }
        for (pubkey, stake) in other {
            *stakes.entry(pubkey).or_default() += stake;
        }
        stakes
    }
    let delegated_stakes = thread_pool.install(|| {
        stake_delegations
            .par_iter()
            .fold(
                DelegatedStakes::default,
                |mut delegated_stakes, (_stake_pubkey, stake_account)| {
                    let delegation = stake_account.delegation();
                    let stake = delegation_effective_stake(
                        delegation,
                        epoch,
                        stake_history,
                        new_rate_activation_epoch,
                        use_fixed_point_stake_math,
                    );
                    if stake != 0 {
                        *delegated_stakes.entry(delegation.voter_pubkey).or_default() += stake;
                    }
                    delegated_stakes
                },
            )
            .reduce(DelegatedStakes::default, merge)
    });
```

**File:** Cargo.toml (L1-1)
```text
[workspace]
```
