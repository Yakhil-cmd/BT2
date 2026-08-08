### Title
Reward-recalculation path uses live/current stake-account state instead of the epoch-boundary snapshot, letting delegators retroactively inflate their share of block rewards — ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
The reward-class from the external report ("using a live/instantaneous value that anyone can mutate, instead of a fixed historical/TWAP-like anchor, in a proportional financial calculation") maps onto Agave's Alpenglow block-reward computation. The denominator of the block-reward split is correctly pinned to an immutable epoch-boundary snapshot (`RewardEpochDelegatedStakes`), but the numerator — an individual delegation's effective stake — is recomputed from the *live* `StakeAccount<Delegation>` fetched from the current `StakesCache` whenever rewards are recalculated (e.g. after a bank restart mid partitioned-distribution), rather than from a value fixed at the same epoch boundary.

### Finding Description
`calculate_block_reward` computes a delegator's share of a vote account's block-revenue reward as:

`(pending_delegator_rewards * stake) / total_active_stake`

where `total_active_stake` is looked up from the immutable, previously-persisted `RewardEpochDelegatedStakes` snapshot, but `stake` is derived via `delegation_effective_stake(delegation, rewarded_epoch, stake_history, ...)` using the **currently stored** `Delegation` (specifically its live `stake` field) rather than a value captured at the same epoch boundary: [1](#0-0) 

The code's own comment acknowledges the asymmetry: `distribution_epoch_vote_accounts` (and by extension the live stake delegations feeding this function) "already includes updated stake activation values from after the new epoch calculation," which is why the *denominator* was hardened to use `RewardEpochDelegatedStakes`: [2](#0-1) 

However, the *numerator* (`stake`) is not similarly pinned. `delegation_effective_stake` computes the historical effective stake for `rewarded_epoch` using `Delegation::stake_v2`/`stake`, which reads the delegation's mutable `stake` (target/fully-warmed) field as it exists *at call time*, combined with the historical `stake_history` entry for warmup/cooldown ratios: [3](#0-2) 

The recalculation path (`recalculate_stake_rewards`, triggered by `recalculate_partitioned_rewards_if_active` whenever the `EpochRewards` sysvar is still `active` — i.e., a normal validator restart/snapshot-load during the multi-slot partitioned rewards distribution window, not a maliciously crafted snapshot) pulls stake delegations from the bank's *current* `StakesCache`: [4](#0-3) [5](#0-4) 

Because a stake account's `delegation.stake` amount can be increased at any time by its (unprivileged) owner via ordinary stake-program instructions (e.g. delegating additional lamports, merging another stake account), an increase performed between the original epoch-boundary reward calculation and a later recalculation causes `delegation_effective_stake` to report a larger "historical" effective stake for `rewarded_epoch` than the delegation actually held during that epoch — inflating that delegator's numerator against the fixed, correctly-pinned `total_active_stake` denominator.

The developers were aware something could go wrong here, adding a clamp: [6](#0-5) 
This clamp only bounds an individual reward to the vote account's total `pending_delegator_rewards`; it does not prevent one delegator's share from crowding out other delegators under the same vote account, since each delegator's fraction is computed independently against the fixed pool.

### Impact Explanation
This results in misattributed rewards: a delegator who increases their stake amount after the epoch boundary (before a recalculation event occurs) can retroactively claim a larger fraction of a fixed, already-capped block-reward pool for a past epoch than they actually earned, at the expense of other delegators to the same vote account whose share is computed against the same fixed denominator and fixed pool. This is a concrete misattribution of lamports between unprivileged stakers, matching the accepted impact category ("misattributed or duplicated rewards").

### Likelihood Explanation
Exploitation requires: (1) an active partitioned Alpenglow block-reward distribution window (`EpochRewards` sysvar `active`), (2) a bank restart or ledger replay that triggers `recalculate_partitioned_rewards_if_active` mid-distribution, and (3) the attacker/delegator performing an ordinary stake top-up in that window. Validator restarts during reward distribution are a normal, expected operational occurrence (not a "maliciously crafted snapshot," which is out of scope), and stake top-ups are unprivileged, routine stake-program actions, making the precondition plausible though timing-dependent and requiring the recalculation trigger to actually occur before distribution completes.

### Recommendation
Pin the numerator the same way the denominator was pinned: persist (or derive) each delegation's effective stake for `rewarded_epoch` in the same `RewardEpochDelegatedStakes`-style immutable snapshot at the epoch boundary, and use that snapshot value in `calculate_block_reward` (and any other epoch-reward numerator) during recalculation, instead of re-deriving it from the live `StakesCache`/`Delegation.stake` field.

### Proof of Concept
Not independently reproduced in this review (no test harness run); the vulnerable code path and the mitigating clamp were both located and cited above. Confidence in the exact end-to-end exploit mechanics (precise triggering conditions for `recalculate_partitioned_rewards_if_active` and whether other guards elsewhere further constrain the manipulation window) is moderate — a background engineering session with test execution would be needed to fully confirm exploitability and quantify the achievable skew.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L183-231)
```rust
    let vote_pubkey = delegation.voter_pubkey;
    let Some(vote_account) = distribution_epoch_vote_accounts.get(&vote_pubkey) else {
        debug!("could not find vote account {vote_pubkey} in cache");
        return 0;
    };
    let vote_state = vote_account.vote_state_view();
    let pending_delegator_rewards = vote_state.pending_delegator_rewards();
    // NOTE: during recalculation, `distribution_epoch_vote_accounts` already
    // includes updated stake activation values from after the new epoch
    // calculation, so we need to use `RewardEpochDelegatedStakes` for the exact
    // values at the end of the reward epoch.
    let (AlpenglowEpochType::Alpenglow {
        reward_epoch_delegated_stakes,
        ..
    }
    | AlpenglowEpochType::MigrationEpoch {
        reward_epoch_delegated_stakes,
        ..
    }) = ag_epoch_type
    else {
        debug!("Alpenglow must be enabled for block reward calculation");
        return 0;
    };
    let total_active_stake = reward_epoch_delegated_stakes
        .delegated_stakes
        .get(&vote_pubkey)
        .copied()
        .unwrap_or(0);
    if total_active_stake == 0 {
        0
    } else {
        let stake = delegation_effective_stake(
            delegation,
            rewarded_epoch,
            stake_history,
            new_warmup_cooldown_rate_epoch,
            use_fixed_point_stake_math,
        );
        // During recalculation, if stake account has already received rewards,
        // it's possible to have `stake > total_active_stake`. If
        // `pending_delegator_rewards` is a huge number, we could potentially
        // overflow a `u64`. We can also have individual rewards look greater
        // than the pending rewards. This is harmless in practice, but we
        // clamp it just to be safe
        (pending_delegator_rewards as u128 * stake as u128 / total_active_stake as u128)
            .try_into()
            .unwrap_or(u64::MAX)
            .min(pending_delegator_rewards)
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L582-608)
```rust
    fn get_epoch_params_for_recalculation<'a>(
        &'a self,
        rewarded_epoch: Epoch,
        stakes: &'a Stakes<StakeAccount<Delegation>>,
    ) -> EpochRewardCalculateParamInfo<'a> {
        // Use `stakes` for stake-related info
        let stake_history = stakes.history().clone();
        let stake_delegations = stakes.stake_delegations_vec();

        // Use the VAT-filtered vote-account snapshot from epoch_stakes.
        // Recalculation should match the vote-account admission policy used for
        // distribution.
        let leader_schedule_epoch = self.epoch_schedule().get_leader_schedule_epoch(self.slot());
        let distribution_epoch_vote_accounts = self
            .epoch_stakes(leader_schedule_epoch)
            .expect("calculation should always run after Bank::update_epoch_stakes()")
            .stakes()
            .vote_accounts();
        let cached_vote_accounts =
            self.get_cached_vote_accounts(rewarded_epoch, distribution_epoch_vote_accounts);

        EpochRewardCalculateParamInfo {
            stake_history,
            stake_delegations,
            cached_vote_accounts,
        }
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1038-1061)
```rust
    fn recalculate_stake_rewards(
        &self,
        epoch_rewards_sysvar: &EpochRewards,
        thread_pool: &ThreadPool,
    ) -> (Arc<PartitionedStakeRewards>, Vec<Vec<usize>>) {
        assert!(epoch_rewards_sysvar.active);
        // If rewards are active, the rewarded epoch is always the immediately
        // preceding epoch.
        let rewarded_epoch = self.epoch().saturating_sub(1);

        let point_value = PointValue {
            rewards: epoch_rewards_sysvar.total_rewards,
            points: epoch_rewards_sysvar.total_points,
        };

        let stakes = self.stakes_cache.stakes();
        let EpochRewardCalculateParamInfo {
            stake_history,
            stake_delegations,
            cached_vote_accounts,
        } = self.get_epoch_params_for_recalculation(rewarded_epoch, &stakes);
        let ag_epoch_type = AlpenglowEpochType::get(self, rewarded_epoch, || {
            RewardEpochDelegatedStakes::get(self)
        });
```

**File:** runtime/src/stake_delegation.rs (L10-23)
```rust
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
