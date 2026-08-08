Based on the code analysis, this attack scenario does not work as a vulnerability in this codebase.

**Key facts that defeat the described attack:**

1. **Commission destination is fixed once per epoch, not re-derived at distribution.** The `commission_pubkey` used for commission payout is captured once during `calculate_stake_rewards_and_commissions`/`redeem_delegation_rewards` (reading `vote_state.inflation_rewards_collector()` from a fixed `distribution_epoch_vote_accounts` snapshot), and stored as the *key* of the `RewardCommissions` HashMap. [1](#0-0) 
Distribution (`load_and_reward_commission_accounts`) iterates that same fixed map and loads/credits whatever account exists at that recorded pubkey — it never re-reads the vote account's *current* collector field to decide where money goes. [2](#0-1) 

2. **Calculation and distribution of commissions are not separated across blocks/epochs.** `distribute_reward_commissions` (which internally calls `load_and_reward_commission_accounts` and `store_commission_accounts_partitioned`) is invoked synchronously inside `begin_partitioned_rewards`, itself called synchronously inside `process_new_epoch` at the epoch boundary. [3](#0-2) [4](#0-3) 
Only *stake* reward distribution is partitioned/deferred across many blocks; commission distribution is a one-shot operation at the epoch boundary. The recalculation path (`recalculate_stake_rewards`) explicitly recomputes reward commissions internally but the code comment states this must never be reused for actual payout — only the stake-reward portion is used. [5](#0-4) 
So there is no "later recalculation" pathway that redirects already-computed commission destinations to a new collector value.

3. **Incinerator-bound lamports are burned (capitalization decremented, account zeroed) within the same block**, via `run_incinerator`, which is called during `freeze()` at the end of block processing. [6](#0-5) 
This happens in the same block in which the commission was credited to the incinerator (since distribution is synchronous with calculation at the epoch boundary), leaving no window where an attacker's reset of `inflation_rewards_collector` back to themselves could reclaim the already-burned lamports — the funds physically no longer exist in any account by the time a subsequent transaction could run.

4. The `accumulate_lamports` merge logic and its accompanying doc comment explicitly discuss and correctly handle the cross-epoch collector-reassignment edge cases (vote-account-becomes-collector scenarios), confirming this exact class of issue was already considered and mitigated in design. [7](#0-6) 

Existing regression tests (`test_inflation_rewards_collector`, `test_repeated_inflation_rewards_collector`, `test_invalid_inflation_rewards_collector_burns_sysvar_rewards`) already exercise toggling the collector across epoch boundaries and assert correct, exactly-once accounting. [8](#0-7) 

#No vulnerability found for this question.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L73-126)
```rust
/// Merge the lamport and `is_vote_account` fields of two `RewardCommission`s
///
/// This pays special attention to the case where `is_vote_account` does not
/// match, which can happen in the following situation:
///
/// * a vote account A sets the inflation collector to valid system account B
/// * at some point in the future, that system account B gets allocated and
///   initialized as a vote account B
/// * vote account B sets itself as the inflation reward collector
///
/// In that situation, the rewards for vote account A will get burned, but the
/// rewards for vote account B will not. According to the rules of SIMD-0232,
/// a collector account must either be the vote account itself or a system
/// account that fulfills certain criteria. In the case of vote account A, we
/// are already sure that the collector account is invalid.
///
/// NOTE: if vote account B sets a system account as its inflation collector,
/// then the commission lamports for vote account A will NOT get burned here,
/// but will get burned during `load_and_reward_commission_accounts`
fn accumulate_lamports(src: &RewardCommission, dst: &mut RewardCommission) {
    match (src.is_vote_account, dst.is_vote_account) {
        (false, true) => {
            // Don't accumulate, burn everything in the source
            // reward commission entry.
            //
            // NOTE: There shouldn't be any burned lamports in the
            // source entry, but we're defensive
            dst.burned_lamports = dst
                .burned_lamports
                .saturating_add(src.commission_lamports)
                .saturating_add(src.burned_lamports);
        }
        (true, false) => {
            // The commission lamports on the source are the only
            // ones that get distributed, all others get burned.
            //
            // NOTE: There shouldn't be any burned lamports in the
            // destination entry, but we're defensive
            dst.is_vote_account = true;
            dst.burned_lamports = dst
                .burned_lamports
                .saturating_add(dst.commission_lamports)
                .saturating_add(src.burned_lamports);
            dst.commission_lamports = src.commission_lamports;
        }
        _ => {
            // Normal case, just accumulate both
            dst.commission_lamports = dst
                .commission_lamports
                .saturating_add(src.commission_lamports);
            dst.burned_lamports = dst.burned_lamports.saturating_add(src.burned_lamports);
        }
    }
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L241-259)
```rust
    pub(in crate::bank) fn begin_partitioned_rewards(
        &mut self,
        parent_epoch: Epoch,
        parent_slot: Slot,
        parent_block_height: u64,
        rewards_calculation: &PartitionedRewardsCalculation,
        rewards_metrics: &mut RewardsMetrics,
        thread_pool: &ThreadPool,
    ) -> u64 {
        let RewardCommissionLamportAmounts {
            distributed_lamports,
            distributed_to_incinerator_lamports,
            burned_lamports,
        } = self.distribute_reward_commissions(
            parent_epoch,
            rewards_calculation,
            rewards_metrics,
            thread_pool,
        );
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1063-1075)
```rust
        // On recalculation, only the `StakeRewardCalculation::stake_rewards`
        // field is relevant. It is assumed that reward commission accounts have
        // already been calculated and delivered, while
        // `StakeRewardCalculation::total_rewards` only reflects rewards that
        // have not yet been distributed.
        //
        // NOTE: the `RewardCommissionAccounts` will NOT have a correct
        // post_lamport amount if the commission account is NOT the vote account,
        // because the commission account is loaded from the current bank, and
        // not the start of the epoch. We don't have a snapshot of all commission
        // accounts from the start of the epoch. For this reason, the
        // `RewardCommissionAccounts` calculated in this function call should
        // NOT be used ever.
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1115-1130)
```rust
        let accounts_with_rewards: Vec<_> = thread_pool.install(|| {
            reward_commissions
                .par_iter()
                .filter_map(
                    |(
                        commission_pubkey,
                        RewardCommission {
                            commission_bps,
                            commission_lamports,
                            burned_lamports,
                            is_vote_account,
                        },
                    )| {
                        let maybe_commission_account =
                            self.get_account_with_fixed_root_no_cache(commission_pubkey);
                        let mut commission_account = if custom_commission_collector {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L3893-3972)
```rust
    #[test]
    fn test_repeated_inflation_rewards_collector() {
        let GenesisConfigInfo {
            mut genesis_config, ..
        } = genesis_utils::create_genesis_config_with_leader(
            1_000_000 * LAMPORTS_PER_SOL,
            &Pubkey::new_unique(),
            42 * LAMPORTS_PER_SOL,
        );

        genesis_config.rent = Rent::default();
        genesis_config.epoch_schedule = EpochSchedule::new(SLOTS_PER_EPOCH);

        let (bank, bank_forks) =
            Bank::new_for_tests(&genesis_config).wrap_with_bank_forks_for_tests();

        let collector_address = Pubkey::new_unique();
        let vote1_address = Pubkey::new_unique();
        let vote2_address = Pubkey::new_unique();
        // Vote account just created
        let bank = apply_epoch_operations(
            bank,
            bank_forks.as_ref(),
            EpochOperations {
                epoch: 0,
                vote_operations: vec![
                    (
                        vote1_address,
                        VoteOperations {
                            create_with_balance: Some(LAMPORTS_PER_SOL),
                            new_commission: Some(50),
                            earned_credits: Some(1000),
                            delegate_stake_amount: Some(LAMPORTS_PER_SOL),
                            new_inflation_rewards_collector: Some(collector_address),
                            ..VoteOperations::default()
                        },
                    ),
                    (
                        vote2_address,
                        VoteOperations {
                            create_with_balance: Some(LAMPORTS_PER_SOL),
                            new_commission: Some(100),
                            earned_credits: Some(1000),
                            delegate_stake_amount: Some(LAMPORTS_PER_SOL),
                            new_inflation_rewards_collector: Some(collector_address),
                            ..VoteOperations::default()
                        },
                    ),
                ],
            },
        );

        // next epoch, get double reward into collector
        let epoch = bank.epoch();
        apply_epoch_operations(
            bank,
            bank_forks.as_ref(),
            EpochOperations {
                epoch,
                vote_operations: vec![
                    (
                        vote1_address,
                        VoteOperations {
                            earned_credits: Some(1),
                            expect_reward: true,
                            ..VoteOperations::default()
                        },
                    ),
                    (
                        vote2_address,
                        VoteOperations {
                            earned_credits: Some(1),
                            expect_reward: true,
                            ..VoteOperations::default()
                        },
                    ),
                ],
            },
        );
    }
```

**File:** runtime/src/bank.rs (L1862-1872)
```rust
        // Distribute rewards commission to vote accounts and cache stake rewards
        // for partitioned distribution in the upcoming slots.
        let (epoch_rewards, begin_partitioned_rewards_time_us) =
            measure_us!(self.begin_partitioned_rewards(
                parent_epoch,
                parent_slot,
                parent_height,
                &rewards_calculation,
                &mut rewards_metrics,
                thread_pool,
            ));
```

**File:** runtime/src/bank.rs (L4528-4535)
```rust
    fn run_incinerator(&self) {
        if let Some((account, _)) =
            self.get_account_modified_since_parent_with_fixed_root(&incinerator::id())
        {
            self.capitalization.fetch_sub(account.lamports(), Relaxed);
            self.store_account(&incinerator::id(), &AccountSharedData::default());
        }
    }
```
