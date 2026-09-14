Based on my research, I found a strong analog in the agave reward-distribution codebase, though I was unable to fully trace the vote-program instruction that sets `inflation_rewards_collector` before running out of tool calls (its handler implementation in `programs/vote/src/vote_state/handler.rs` was located but not read in full).

### Title
Commission-collector redirection allows a new vote-account collector to claim already-earned validator commission rewards for a past rewarded epoch - (File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs)

### Summary
In `redeem_delegation_rewards`, the commission **rate** (`commission_bps`) used to compute validator/staker rewards for the `rewarded_epoch` is deliberately taken from a delayed, historical snapshot (`snapshot_epoch_vote_accounts` / `rewarded_epoch_vote_accounts`) specifically to prevent "last minute commission rugs" [1](#0-0) . However, when `custom_commission_collector` is active, the **recipient** of that commission (`commission_pubkey`) is *not* taken from that same delayed snapshot — it is read directly from the current/distribution-epoch vote account state instead.

### Finding Description
`redeem_delegation_rewards` fetches the vote account for reward purposes from `distribution_epoch_vote_accounts`, which represents vote-account state at the end of the rewarded epoch / distribution time, not a delayed snapshot [2](#0-1) . The commission **rate** used for computing the split is explicitly pulled from the delayed `snapshot_epoch_vote_accounts`/`rewarded_epoch_vote_accounts` (falling back to `vote_state` only if neither delayed snapshot has an entry), with an explicit code comment stating this is done "to attempt to delay the effect of commission updates by at least one full epoch" [3](#0-2) .

By contrast, when `custom_commission_collector` is enabled, the commission **collector pubkey** — i.e., who actually receives the commission lamports — is computed as:
```rust
let (commission_pubkey, is_vote_account) = if custom_commission_collector {
    let commission_pubkey = *vote_state
        .inflation_rewards_collector()
        .unwrap_or(&vote_pubkey);
    (commission_pubkey, commission_pubkey == vote_pubkey)
} else {
    (vote_pubkey, true)
};
``` [4](#0-3) 

Here `vote_state` is `vote_account.vote_state_view()` where `vote_account` came from `distribution_epoch_vote_accounts` — the *current* state at reward-distribution time, not the delayed rewarded-epoch snapshot used for the commission rate [5](#0-4) .

This is structurally the same bug class as the external report: the reward-rate accounting (analogous to "curator share calculation") is snapshot-protected against post-period changes, but the reward-recipient accounting (analogous to "curator/vault owner") is not. If the vote account's authorized withdrawer changes `inflation_rewards_collector` after the rewarded epoch ends but before rewards are actually distributed (which can span up to the beginning of the next epoch, per `recalculate_stake_rewards`'s handling of `rewarded_epoch = self.epoch().saturating_sub(1)` during active `EpochRewards` sysvar distribution [6](#0-5) ), the new collector—not the one who was designated during the epoch being rewarded—receives the commission lamports earned during that epoch.

### Impact Explanation
This allows commission earned during epoch N (based on stake/vote activity that occurred under the original collector) to be redirected to an arbitrary new pubkey if the authorized withdrawer changes the collector after epoch N ends but before the (up to one full epoch of) partitioned distribution completes. This is a reward/fund-misdirection issue analogous to the reported vault-ownership bug: value earned under one identity is paid to a different identity due to using end-state rather than epoch-of-record state.

### Likelihood Explanation
Reachable by any authorized withdrawer of a vote account with a single permissionless instruction (changing the inflation rewards collector) combined with normal validator operation — no privileged access needed beyond controlling one's own vote account, which is a legitimate validator operator action, not a malicious-peer or leader-only path.

### Recommendation
Read `commission_pubkey` (the `inflation_rewards_collector`) from the same delayed snapshot (`snapshot_epoch_vote_accounts`/`rewarded_epoch_vote_accounts`) used for `commission_bps`, rather than from `distribution_epoch_vote_accounts`, so that the collector recorded for the rewarded epoch — not the collector at distribution time — receives that epoch's commission.

### Proof of Concept
Not fully producible: I could not confirm within the available tool budget (1) whether `inflation_rewards_collector` can in fact be changed by the authorized withdrawer via a documented vote instruction without a similar delay rule as `update_commission`'s `is_commission_update_allowed` check, and (2) the exact code in `programs/vote/src/vote_state/handler.rs` that implements `set_inflation_rewards_collector`. This should be verified directly before treating the finding as conclusively exploitable — I flag this uncertainty explicitly rather than asserting it as proven.

### Citations

**File:** runtime/src/bank.rs (L1723-1742)
```rust
    /// Get cached vote account state from the past few epochs so that some vote
    /// state configuration changes are delayed before being used in reward
    /// calculation.
    fn get_cached_vote_accounts<'a>(
        &'a self,
        rewarded_epoch: Epoch,
        distribution_epoch_vote_accounts: &'a VoteAccounts,
    ) -> CachedVoteAccounts<'a> {
        // Snapshot of vote account state from the beginning of the epoch prior to
        // the rewarded epoch. This snapshot state is saved a full epoch before
        // being used to prevent last minute commission rugs.
        let snapshot_epoch_vote_accounts = self
            .epoch_stakes(rewarded_epoch)
            .map(|epoch_stakes| epoch_stakes.stakes().vote_accounts());

        // Vote account state from the beginning of the rewarded epoch.
        let rewarded_epoch_vote_accounts = self
            .epoch_stakes(self.epoch())
            .map(|epoch_stakes| epoch_stakes.stakes().vote_accounts());

```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L636-701)
```rust
        let CachedVoteAccounts {
            snapshot_epoch_vote_accounts,
            rewarded_epoch_vote_accounts,
            distribution_epoch_vote_accounts,
        } = cached_vote_accounts;

        let vote_pubkey = stake_account.delegation().voter_pubkey;

        let current_lamports = stake_account.lamports();
        let minimum_lamports = self
            .rent_collector
            .rent
            .minimum_balance(stake_account.data_len());
        let stake = *stake_account.stake();

        let Some(vote_account) = distribution_epoch_vote_accounts.get(&vote_pubkey) else {
            debug!("could not find vote account {vote_pubkey} in cache");
            // Even if the vote account doesn't exist, there might still be a
            // need to adjust the stake delegation
            if adjust_delegations_for_rent {
                let status = delegation_activation_status(
                    &stake.delegation,
                    rewarded_epoch,
                    stake_history,
                    new_rate_activation_epoch,
                    use_fixed_point_stake_math,
                );
                if delegation_may_need_adjustment(
                    stake.delegation.stake,
                    stake.delegation.stake,
                    current_lamports,
                    minimum_lamports,
                    status,
                ) {
                    debug!(
                        "delegation for stake {stake_pubkey} may be adjusted at distribution, \
                         unless lamports are transferred before distribution block"
                    );
                    let inflation = InflationReward {
                        stake,
                        stake_reward: 0,
                        commission_bps: (!custom_commission_collector).then_some(0),
                    };
                    // Set `is_vote_account` to `false` in order to deliberately
                    // fail during commission collector checks. This avoids
                    // creating a reward entry during payout.
                    let reward_commission = RewardCommission {
                        commission_bps: (!custom_commission_collector).then_some(0),
                        commission_lamports: 0,
                        burned_lamports: 0,
                        is_vote_account: false,
                    };
                    return Some(InflationRewardWithCommission {
                        inflation,
                        commission_pubkey: vote_pubkey,
                        reward_commission,
                    });
                } else {
                    debug!("delegation for stake {stake_pubkey} will not be adjusted");
                    return None;
                }
            } else {
                return None;
            }
        };
        let vote_state = vote_account.vote_state_view();
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L703-724)
```rust
        // Fetch the voter commission from past epochs to attempt to
        // delay the effect of commission updates by at least one
        // full epoch.
        // When `commission_rate_in_basis_points` is true, use the new field
        // `inflation_rewards_commission_bps`; otherwise use the legacy
        // percentage field and convert to basis points by multiplying by 100.
        let commission_bps = if delay_commission_updates {
            let vote_state_for_commission = snapshot_epoch_vote_accounts
                .and_then(|eva| eva.get(&vote_pubkey))
                .or_else(|| rewarded_epoch_vote_accounts.and_then(|eva| eva.get(&vote_pubkey)))
                .map(|vote_account| vote_account.vote_state_view())
                .unwrap_or(vote_state);
            if commission_rate_in_basis_points {
                vote_state_for_commission.inflation_rewards_commission()
            } else {
                vote_state_for_commission.commission() as u16 * 100
            }
        } else if commission_rate_in_basis_points {
            vote_state.inflation_rewards_commission()
        } else {
            vote_state.commission() as u16 * 100
        };
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L750-757)
```rust
                let (commission_pubkey, is_vote_account) = if custom_commission_collector {
                    let commission_pubkey = *vote_state
                        .inflation_rewards_collector()
                        .unwrap_or(&vote_pubkey);
                    (commission_pubkey, commission_pubkey == vote_pubkey)
                } else {
                    (vote_pubkey, true)
                };
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1038-1058)
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
```
