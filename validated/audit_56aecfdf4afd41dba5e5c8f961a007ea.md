### Title
Rewards can be silently burned (never paid to anyone) when a stake account is merged/closed between reward calculation and partitioned distribution - (File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs)

### Summary
Solana's partitioned epoch-rewards mechanism computes stake rewards for every delegated stake account in a "calculation" phase at the epoch boundary, then pays them out over several subsequent blocks in a "distribution" phase. If the referenced stake account is removed from the `StakesCache` (e.g. merged into another account or otherwise made non-delegated) after calculation but before its partition is distributed, `build_updated_stake_reward()` returns `DistributionError::AccountNotFound` and the corresponding stake reward is silently discarded from `capitalization` instead of being paid to the staker. This mirrors the referenced Crowdsale bug class: a value computed against an earlier snapshot ("finalize()"/`auctionEnded()`) is invalidated by a later unprivileged action (`commitEth`/`commitTokens`) that the code assumed could not happen, resulting in funds becoming permanently unrecoverable.

### Finding Description
Reward calculation happens once, at the epoch boundary, from a snapshot of the `stakes_cache`: [1](#0-0) 

The resulting `PartitionedStakeRewards` list is partitioned and distributed across up to `num_partitions` subsequent blocks: [2](#0-1) 

For each stake pubkey scheduled for a reward, `build_updated_stake_reward()` looks the pubkey up in the *current* `stakes_cache` (not the snapshot taken during calculation) and fails if it is no longer present: [3](#0-2) 

`store_stake_accounts_in_partition()` explicitly handles this failure by burning the reward amount rather than crediting it to anyone: [4](#0-3) 

The function's own doc comment concedes the assumption this relies on: that "stake accounts are checked in calculation, and further state mutation [is] prevent[ed] by stake-program restrictions," so "there should never be rewards burned": [5](#0-4) 

However, no such restriction was found anywhere in the stake-program instruction handlers gating `merge`/`split`/`deactivate`/`withdraw` on `EpochRewards.active`; a grep for any `EpochRewardsActive`-style guard only turns up bank-internal sysvar/RPC code, not stake-program instruction processing. Tests in this codebase confirm merges are freely allowed shortly after activation/around reward periods, e.g. `stake_merge_immediately_after_activation`, which merges a stake account into another right after the reward interval without any special restriction being exercised: [6](#0-5) 

Because the distribution phase can span up to 10% of an epoch's slots (`get_reward_distribution_num_blocks`), there is a real window between calculation and a given account's specific distribution partition slot during which the staker (an ordinary, unprivileged stake authority) can submit a `Merge` (or equivalent account-removing) instruction for their own stake account, removing the `Pubkey` entry from `stakes_cache.stake_delegations()` that the pending `PartitionedStakeReward` still references: [7](#0-6) 

When that account's partition is later processed, `build_updated_stake_reward` returns `AccountNotFound`, and the reward for that stake is added to `stake_reward_lamports_burned` and never paid to the staker (nor to the account it was merged into, since the merged-into account already got its own, separately-calculated reward for the pre-merge stake amount). This is exactly analogous to the referenced bug: an assumption ("this account can no longer change state") baked into a value computed earlier is violated by a legitimate, unprivileged action taken in the intervening window, causing funds to be irrecoverably lost.

### Impact Explanation
Reward lamports intended for a legitimate staker are unilaterally burned from `capitalization` instead of being distributed, i.e. lamports the protocol accounted for as "to be minted to a specific staker" are dropped. This is a direct loss/misattribution of rewards for an ordinary, unprivileged user action (merging one's own stake account), not requiring any validator/operator privilege, and matches the "misattributed or duplicated rewards" acceptance criterion.

### Likelihood Explanation
The distribution window can last many blocks (up to `slots_per_epoch / 10`), giving ample opportunity for a staker to submit a normal `Merge`/`Deactivate`+`Withdraw`/`Split` sequence against their own stake account after it has been selected for a reward in the calculation phase but before its specific partition slot is processed. No feature flag or extra condition is required beyond partitioned epoch rewards being enabled (which is already the default distribution mechanism in this codebase, as evidenced throughout `partitioned_epoch_rewards`). The main uncertainty is whether some out-of-band mechanism elsewhere (not found via search, possibly in an area outside the indexed portion of the codebase) actually blocks stake mutation while `EpochRewards.active`; this was not located despite targeted searches, and the code's own doc comments in `distribution.rs` acknowledge the fragility of this assumption.

### Recommendation
Either (a) reject/skip stake-program instructions (`Merge`, `Split`, `DeactivateStake`, `Withdraw`) that would remove or alter a stake account while `EpochRewards.active` is true and that account still has a pending, undistributed `PartitionedStakeReward`, or (b) recalculate/redirect (rather than burn) any reward whose target account disappears mid-distribution, e.g. by re-crediting it to the merged-into account or refunding it via a recoverable path instead of silently reducing `capitalization`. At minimum, `store_stake_accounts_in_partition` should treat `AccountNotFound` as an invariant violation to be alerted/metriced loudly (it already logs an `error!`, but the reward is still permanently lost) rather than a silently accepted "burn" case.

### Proof of Concept
1. At an epoch boundary, `calculate_rewards_for_partitioning` computes a `PartitionedStakeReward` for stake account `S`, delegated to vote account `V`, based on the calculation-time `stakes_cache` snapshot.
2. `begin_partitioned_rewards` schedules `S`'s reward for a distribution partition several blocks later (`get_reward_distribution_num_blocks` can span up to `slots_per_epoch/10` blocks).
3. Before `S`'s partition slot is reached, the stake authority submits a `Merge` instruction merging `S` into another stake account `S2` (a normal, unprivileged stake-program instruction with no epoch-rewards-active check found).
4. `S` is removed from `stakes_cache.stake_delegations()`.
5. When `S`'s partition is later processed, `build_updated_stake_reward` fails with `DistributionError::AccountNotFound` at [3](#0-2) , and `store_stake_accounts_in_partition` burns `S`'s reward amount instead of paying it to anyone, per [8](#0-7) .

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L470-481)
```rust
    /// Calculate rewards from previous epoch to prepare for partitioned distribution.
    pub(super) fn calculate_rewards_for_partitioning<'a>(
        &self,
        stake_history: &StakeHistory,
        stake_delegations: Vec<(&'a Pubkey, &'a StakeAccount<Delegation>)>,
        cached_vote_accounts: CachedVoteAccounts<'_>,
        rewarded_epoch: Epoch,
        reward_epoch_delegated_stakes: RewardEpochDelegatedStakes,
        reward_calc_tracer: Option<impl Fn(&RewardCalculationEvent) + Send + Sync>,
        thread_pool: &ThreadPool,
        metrics: &mut RewardsMetrics,
    ) -> PartitionedRewardsCalculation {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L78-149)
```rust
impl Bank {
    /// Process reward distribution for the block if it is inside reward interval.
    pub(in crate::bank) fn distribute_partitioned_epoch_rewards(&mut self) {
        let EpochRewardStatus::Active(status) = &self.epoch_reward_status else {
            return;
        };

        let distribution_starting_block_height = match &status {
            EpochRewardPhase::Calculation(status) => status.distribution_starting_block_height,
            EpochRewardPhase::Distribution(status) => status.distribution_starting_block_height,
        };

        let height = self.block_height();
        if height < distribution_starting_block_height {
            return;
        }

        if let EpochRewardPhase::Calculation(status) = &status {
            // epoch rewards have not been partitioned yet, so partition them now
            // This should happen only once immediately on the first rewards distribution block, after reward calculation block.
            let epoch_rewards_sysvar = self.get_epoch_rewards_sysvar();
            let (partition_indices, partition_us) = measure_us!({
                epoch_rewards_hasher::hash_rewards_into_partitions(
                    &status.all_stake_rewards,
                    &epoch_rewards_sysvar.parent_blockhash,
                    epoch_rewards_sysvar.num_partitions as usize,
                )
            });

            // update epoch reward status to distribution phase
            self.set_epoch_reward_status_distribution(
                distribution_starting_block_height,
                Arc::clone(&status.all_stake_rewards),
                partition_indices,
            );

            datapoint_info!(
                "epoch-rewards-status-update",
                ("slot", self.slot(), i64),
                ("block_height", height, i64),
                ("partition_us", partition_us, i64),
                (
                    "distribution_starting_block_height",
                    distribution_starting_block_height,
                    i64
                ),
            );
        }

        let EpochRewardStatus::Active(EpochRewardPhase::Distribution(partition_rewards)) =
            &self.epoch_reward_status
        else {
            // We should never get here.
            unreachable!(
                "epoch rewards status is not in distribution phase, but we are trying to \
                 distribute rewards"
            );
        };

        let distribution_end_exclusive =
            distribution_starting_block_height + partition_rewards.partition_indices.len() as u64;

        assert!(
            self.epoch_schedule.get_slots_in_epoch(self.epoch)
                > partition_rewards.partition_indices.len() as u64
        );

        if height >= distribution_starting_block_height && height < distribution_end_exclusive {
            let partition_index = height - distribution_starting_block_height;

            self.distribute_epoch_rewards_in_partition(partition_rewards, partition_index);
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-252)
```rust
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L327-335)
```rust
    /// Store stake rewards in partition
    /// Returns DistributionResults containing the sum of all the rewards
    /// stored, the sum of all rewards burned, and the updated StakeRewards.
    /// Because stake accounts are checked in calculation, and further state
    /// mutation prevents by stake-program restrictions, there should never be
    /// rewards burned.
    ///
    /// Note: even if staker's reward is 0, the stake account still needs to be
    /// stored because credits observed has changed
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L393-407)
```rust
            ) {
                Ok(stake_reward) => {
                    stake_reward_lamports_minted += stake_reward_amount;
                    block_reward_lamports_distributed += block_reward_amount;
                    updated_stake_rewards.push(stake_reward);
                }
                Err(err) => {
                    error!(
                        "bank::distribution::store_stake_accounts_in_partition() failed for \
                         {stake_pubkey}, {stake_reward_amount} lamports burned: {err:?}"
                    );
                    stake_reward_lamports_burned += stake_reward_amount;
                    block_reward_lamports_burned += block_reward_amount;
                }
            }
```

**File:** program-test/tests/warp.rs (L224-321)
```rust
#[tokio::test]
async fn stake_merge_immediately_after_activation() {
    let program_test = ProgramTest::default();
    let mut context = program_test.start_with_context().await;

    context.warp_to_slot(100).unwrap();
    let vote_address = setup_vote(&mut context).await;
    context.increment_vote_account_credits(&vote_address, 100);

    let first_normal_slot = context.genesis_config().epoch_schedule.first_normal_slot;
    let slots_per_epoch = context.genesis_config().epoch_schedule.slots_per_epoch;
    let mut current_slot = first_normal_slot + slots_per_epoch;
    context.warp_to_slot(current_slot).unwrap();
    context.warp_forward_force_reward_interval_end().unwrap();

    // this is annoying, but if no stake has earned rewards, the bank won't
    // iterate through the stakes at all, which means we can only test the
    // behavior of advancing credits observed if another stake is earning rewards

    // make a base stake which receives rewards
    let user_keypair = Keypair::new();
    let stake_lamports = 1_000_000_000_000;
    let base_stake_address =
        setup_stake(&mut context, &user_keypair, &vote_address, stake_lamports).await;
    check_credits_observed(&mut context.banks_client, base_stake_address, 100).await;
    context.increment_vote_account_credits(&vote_address, 100);

    let clock_account = context
        .banks_client
        .get_account(clock::id())
        .await
        .expect("account exists")
        .unwrap();
    let clock: Clock = deserialize(&clock_account.data).unwrap();
    context.warp_to_epoch(clock.epoch + 1).unwrap();
    current_slot += slots_per_epoch;
    context.warp_forward_force_reward_interval_end().unwrap();

    // make another stake which will just have its credits observed advanced
    let absorbed_stake_address =
        setup_stake(&mut context, &user_keypair, &vote_address, stake_lamports).await;
    // the new stake is at the right value
    check_credits_observed(&mut context.banks_client, absorbed_stake_address, 200).await;
    // the base stake hasn't been moved forward because no rewards were earned
    check_credits_observed(&mut context.banks_client, base_stake_address, 100).await;

    context.increment_vote_account_credits(&vote_address, 100);
    current_slot += slots_per_epoch;
    context.warp_to_slot(current_slot).unwrap();
    context.warp_forward_force_reward_interval_end().unwrap();

    // check that base stake has earned rewards and credits moved forward
    let stake_account = context
        .banks_client
        .get_account(base_stake_address)
        .await
        .unwrap()
        .unwrap();
    let stake_state: StakeStateV2 = deserialize(&stake_account.data).unwrap();
    assert_eq!(stake_state.stake().unwrap().credits_observed, 300);
    assert!(stake_account.lamports > stake_lamports);

    // check that new stake hasn't earned rewards, but that credits_observed have been advanced
    let stake_account = context
        .banks_client
        .get_account(absorbed_stake_address)
        .await
        .unwrap()
        .unwrap();
    let stake_state: StakeStateV2 = deserialize(&stake_account.data).unwrap();
    assert_eq!(stake_state.stake().unwrap().credits_observed, 300);
    assert_eq!(stake_account.lamports, stake_lamports);

    // sanity-check that the activation epoch was actually last epoch
    let clock_account = context
        .banks_client
        .get_account(clock::id())
        .await
        .unwrap()
        .unwrap();
    let clock: Clock = deserialize(&clock_account.data).unwrap();
    assert_eq!(
        clock.epoch,
        stake_state.delegation().unwrap().activation_epoch + 1
    );

    // sanity-check that it's possible to merge the just-activated stake with the older stake!
    let transaction = Transaction::new_signed_with_payer(
        &stake_instruction::merge(
            &base_stake_address,
            &absorbed_stake_address,
            &user_keypair.pubkey(),
        ),
        Some(&context.payer.pubkey()),
        &vec![&context.payer, &user_keypair],
        context.last_blockhash,
    );
    context
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L408-428)
```rust
    /// Calculate the number of blocks required to distribute rewards to all stake accounts.
    pub(super) fn get_reward_distribution_num_blocks(
        &self,
        rewards: &PartitionedStakeRewards,
    ) -> u64 {
        let total_stake_accounts = rewards.num_rewards();
        if self.epoch_schedule.warmup && self.epoch < self.first_normal_epoch() {
            1
        } else {
            const MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH: u64 = 10;
            let num_chunks = total_stake_accounts
                .div_ceil(self.partitioned_rewards_stake_account_stores_per_block() as usize)
                as u64;

            // Limit the reward credit interval to 10% of the total number of slots in a epoch
            num_chunks.clamp(
                1,
                (self.epoch_schedule.slots_per_epoch / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH).max(1),
            )
        }
    }
```
