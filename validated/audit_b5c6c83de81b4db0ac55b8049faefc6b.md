Based on my research, I found a strong analog to the reported bug class: a validator-set commission rate that is silently ignored in one of two parallel reward-payout code paths, causing stakers to receive a share of rewards that bypasses the intended fee.

### Title
Block-revenue-sharing rewards bypass `block_revenue_commission_bps`, unlike the parallel inflation-reward path that correctly applies `inflation_rewards_commission_bps` - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
The vote account state maintains two independent commission rates: `inflation_rewards_commission_bps` for the legacy per-epoch inflation stake rewards, and `block_revenue_commission_bps` for the newer SIMD-0123/0232 block-revenue-sharing rewards deposited via `deposit_delegator_rewards` into `pending_delegator_rewards` [1](#0-0) . When epoch rewards are calculated, the inflation-reward path (`redeem_delegation_rewards`) correctly fetches `commission_bps` from the vote state and applies a proper `commission_split`/`redeem_rewards` computation before crediting the staker and the commission collector separately [2](#0-1) . However, the parallel `calculate_block_reward` function — which computes each stake account's pro-rata share of the vote account's `pending_delegator_rewards` — never reads or applies `block_revenue_commission_bps` at all; it distributes the raw pro-rata share directly [3](#0-2) .

### Finding Description
`calculate_stake_rewards_and_commissions` invokes `calculate_block_reward` (when `block_revenue_sharing` is enabled) purely to compute a stake-weighted share of `pending_delegator_rewards`, and this `block_reward` value is bundled into `PartitionedStakeReward` alongside — but structurally separate from — the inflation-reward `commission_bps`/`RewardCommission` accounting [4](#0-3) . During actual payout, `build_updated_stake_reward` adds `block_reward` directly to the stake account's lamports with no commission deduction, whereas `inflation.stake_reward` is the commission-adjusted value returned by `redeem_rewards` [5](#0-4) . Meanwhile, `RewardCommission`/`reward_commissions` (used later in `distribute_reward_commissions` and `load_and_reward_commission_accounts` to actually pay the commission collector) is populated only from the inflation-rewards path [6](#0-5) . A grep across the codebase shows `block_revenue_commission_bps`/`block_revenue_commission()` is only ever set, serialized, or displayed (vote program instruction handlers, CLI, account parsers) — it is never read inside `runtime/src/bank/partitioned_epoch_rewards/calculation.rs` or `runtime/src/inflation_rewards/mod.rs`, i.e., nowhere in the reward-calculation/distribution pipeline. This mirrors the sudoswap bug class precisely: two logically-parallel operations (rewarding stakers from two different revenue sources) should both apply their governing commission/fee rate, but only one path (`redeem_delegation_rewards`, the inflation path) does so, while the other (`calculate_block_reward`, the block-revenue path) enforces zero commission regardless of what the validator configured in `block_revenue_commission_bps`.

### Impact Explanation
This is a misattributed-rewards bug: whatever `block_revenue_commission_bps` a validator sets is entirely unenforced for the pending_delegator_rewards distribution path. Delegators effectively receive commission-free block-revenue rewards while the vote account's `block_revenue_collector` never receives its intended cut, silently redirecting funds between accounts contrary to on-chain configured commission state — a concrete misattribution of rewards affecting the epoch reward distribution path.

### Likelihood Explanation
This triggers automatically and deterministically for every epoch reward distribution once `block_revenue_sharing` is enabled and any vote account has a non-zero `pending_delegator_rewards` balance and a non-zero `block_revenue_commission_bps` — no adversarial input is required, only ordinary use of the SIMD-0123 deposit-delegator-rewards feature.

### Recommendation
`calculate_block_reward` (or its caller) should apply `block_revenue_commission_bps` via the same `commission_split`/`commission_split_preserve_lamports` logic used for inflation rewards, crediting the voter's share to the vote account's `block_revenue_collector` and only the staker's share to the stake account, and this commission amount should be folded into `RewardCommission`/`reward_commissions` in `calculate_stake_rewards_and_commissions` so it is distributed through the existing commission-account payout path.

### Proof of Concept
Not independently executable from static review; conceptually: set a vote account's `block_revenue_commission_bps` to e.g. 5000 (50%), deposit lamports via `DepositDelegatorRewards` into `pending_delegator_rewards`, and observe (via `calculate_block_reward`/`build_updated_stake_reward` at epoch boundary) that 100% of the pro-rata share is credited to each delegator's stake account with none diverted to `block_revenue_collector`, contradicting the configured 50% commission — analogous to how `LSSVMPairERC1155.swapTokenForAnyNFTs()` silently applied `tradeFee` instead of the intended `2*tradeFee`.

**Caveat / uncertainty:** I was unable to trace, within the available search iterations, any location outside `runtime/src/bank/partitioned_epoch_rewards/` or `runtime/src/inflation_rewards/` (e.g. in validator client-side reward-forwarding logic) where `block_revenue_commission_bps` might still be honored before or after `DepositDelegatorRewards` is invoked. If such enforcement exists elsewhere (e.g., off-chain in the block-revenue-sharing agent that decides how much to deposit into `pending_delegator_rewards` in the first place, deducting commission before the deposit), the finding above would be a false positive because the effective commission-adjustment would already have happened before the deposit reaches the vote account. This should be verified against the SIMD-0123 design docs and any off-chain agent code before treating this as confirmed.

### Citations

**File:** account-decoder/src/parse_vote.rs (L43-47)
```rust
        inflation_rewards_commission_bps: vote_state.inflation_rewards_commission_bps,
        inflation_rewards_collector: vote_state.inflation_rewards_collector.to_string(),
        block_revenue_collector: vote_state.block_revenue_collector.to_string(),
        block_revenue_commission_bps: vote_state.block_revenue_commission_bps,
        pending_delegator_rewards: vote_state.pending_delegator_rewards.to_string(),
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L173-231)
```rust
/// Calculates block reward for a stake account based on SIMD-0123
fn calculate_block_reward(
    rewarded_epoch: Epoch,
    delegation: &Delegation,
    stake_history: &StakeHistory,
    distribution_epoch_vote_accounts: &VoteAccounts,
    ag_epoch_type: &AlpenglowEpochType,
    new_warmup_cooldown_rate_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
) -> u64 {
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L703-769)
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

        match redeem_rewards(
            stake,
            commission_bps,
            DelegatedVoteState::from(vote_state),
            CalculationEnvironment {
                rewarded_epoch,
                point_value,
                stake_history,
                new_rate_activation_epoch,
                commission_rate_in_basis_points,
                adjust_delegations_for_rent,
                use_fixed_point_stake_math,
            },
            reward_calc_tracer,
            ag_epoch_type,
            current_lamports,
            minimum_lamports,
        ) {
            Ok((stake_reward, commission_lamports, stake)) => {
                let inflation = InflationReward {
                    stake,
                    stake_reward,
                    commission_bps: (!custom_commission_collector).then_some(commission_bps),
                };
                let (commission_pubkey, is_vote_account) = if custom_commission_collector {
                    let commission_pubkey = *vote_state
                        .inflation_rewards_collector()
                        .unwrap_or(&vote_pubkey);
                    (commission_pubkey, commission_pubkey == vote_pubkey)
                } else {
                    (vote_pubkey, true)
                };
                let reward_commission = RewardCommission {
                    commission_bps: (!custom_commission_collector).then_some(commission_bps),
                    commission_lamports,
                    burned_lamports: 0,
                    is_vote_account,
                };
                Some(InflationRewardWithCommission {
                    inflation,
                    commission_pubkey,
                    reward_commission,
                })
            }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L820-893)
```rust
                .filter_map(|((stake_pubkey, stake_account), reward_ref)| {
                    let block_reward = if block_revenue_sharing {
                        calculate_block_reward(
                            rewarded_epoch,
                            stake_account.delegation(),
                            stake_history,
                            cached_vote_accounts.distribution_epoch_vote_accounts,
                            ag_epoch_type,
                            new_warmup_cooldown_rate_epoch,
                            use_fixed_point_stake_math,
                        )
                    } else {
                        0
                    };
                    let maybe_reward_record = self.redeem_delegation_rewards(
                        rewarded_epoch,
                        stake_pubkey,
                        stake_account,
                        &point_value,
                        stake_history,
                        &cached_vote_accounts,
                        reward_calc_tracer.as_ref(),
                        new_warmup_cooldown_rate_epoch,
                        delay_commission_updates,
                        commission_rate_in_basis_points,
                        adjust_delegations_for_rent,
                        ag_epoch_type,
                        custom_commission_collector,
                        use_fixed_point_stake_math,
                    );

                    let (reward, maybe_reward_record) = match (block_reward, maybe_reward_record) {
                        (0, None) => (None, None),
                        (_, Some(res)) => {
                            let InflationRewardWithCommission {
                                inflation,
                                commission_pubkey,
                                reward_commission,
                            } = res;
                            let stake_reward = inflation.stake_reward;
                            (
                                Some(PartitionedStakeReward {
                                    stake_pubkey: **stake_pubkey,
                                    inflation,
                                    block_reward,
                                }),
                                Some(RewardAccumulation {
                                    stake_reward,
                                    commission: Some((commission_pubkey, reward_commission)),
                                }),
                            )
                        }
                        (_, None) => {
                            // Create a zero entry for distribution
                            let stake = *stake_account.stake();
                            let stake_reward = 0;
                            (
                                Some(PartitionedStakeReward {
                                    stake_pubkey: **stake_pubkey,
                                    inflation: InflationReward {
                                        stake,
                                        stake_reward,
                                        commission_bps: None,
                                    },
                                    block_reward,
                                }),
                                // Need a reward record for accumulator
                                Some(RewardAccumulation {
                                    stake_reward,
                                    commission: None,
                                }),
                            )
                        }
                    };
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L262-267)
```rust
        account
            .checked_add_lamports(partitioned_stake_reward.inflation.stake_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
        account
            .checked_add_lamports(partitioned_stake_reward.block_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
```
