### Title
Stake rewards computed during epoch-boundary calculation are silently burned (not credited or refunded) if the stake account is closed before the later distribution partition runs - (File: `runtime/src/bank/partitioned_epoch_rewards/distribution.rs`)

### Summary
Partitioned epoch rewards are computed once, at the epoch boundary, from a snapshot of the `StakesCache`, and then paid out lamport-by-lamport across many subsequent blocks (`distribution_starting_block_height` through `distribution_end_exclusive`). If the stake account referenced by an already-computed reward no longer exists in the `StakesCache` when its partition is finally processed, the reward is treated as a hard failure and the earmarked lamports are burned instead of being paid to the staker, exactly as in the C4 VADER bug where a pre-committed "entitlement" (the merkle proof) becomes permanently unusable once the on-chain state diverges from what was assumed when the entitlement was created.

### Finding Description
`begin_partitioned_rewards` calculates rewards for every delegated stake account and stores that calculation (`all_stake_rewards`) for later, partitioned payout [1](#0-0) . Distribution of a given partition happens many blocks later in `distribute_epoch_rewards_in_partition` → `store_stake_accounts_in_partition` [2](#0-1) .

At distribution time, each pre-computed reward is applied by looking the stake account back up in the *current* `StakesCache` snapshot via `build_updated_stake_reward`: [3](#0-2) 

If the account is not present anymore, the function returns `DistributionError::AccountNotFound`, and the caller treats this as an unrecoverable failure: the reward is burned rather than credited or retried: [4](#0-3) 

A stake account can legitimately disappear from `StakesCache` between the calculation block and its assigned distribution partition through a completely unprivileged, normal user action: the staker fully deactivates and withdraws their stake (`DeactivateStake` + `WithdrawStake`) inside that window, which the CLI/RPC surface exposes and exercises routinely [5](#0-4) . Because the reward for that epoch was already computed and "locked in" at the calculation block using the old stake balance/delegation, but the account is gone (or its state has otherwise diverged) by the time the specific partition is processed, the previously-earned reward for that epoch is discarded permanently: there is no mechanism to re-credit it to the user (e.g. via a separate claimable balance), unlike the recommended VADER fix of decoupling "entitlement" from "point-in-time execution."

This mirrors the reported bug class precisely: an eligibility/entitlement is fixed at one point in time (merkle proof / reward calculation), but the actual payout is deferred and contingent on state that the same unprivileged user can change, and any mismatch causes the entitlement to be irrecoverably lost rather than gracefully handled or retried.

### Impact Explanation
The affected user permanently loses an already-earned staking reward for the epoch (lamports are subtracted from the "distributed" bucket and effectively burned/dropped rather than paid, per the `stake_reward_lamports_burned` accounting) [6](#0-5) . While this doesn't let anyone steal or mint extra lamports, it is a concrete, protocol-level loss of legitimately accrued rewards belonging to a specific staker, which is analogous to the "user permanently locked out of a valuable, already-computed entitlement" impact described in the source report. This is a low/medium severity issue since it is self-inflicted by the affected account's own withdrawal timing and does not affect protocol solvency or other users.

### Likelihood Explanation
This requires a user to close/withdraw their entire delegated stake precisely within the multi-block reward distribution window after their reward has already been calculated for that epoch — a narrow but realistic and reachable window given that the distribution phase spans `num_partitions` blocks and stakers can submit `DeactivateStake`/`WithdrawStake` at any time using ordinary CLI/RPC commands.

### Recommendation
Decouple the "reward is owed" bookkeeping from the "stake account must still exist unchanged" assumption at distribution time, analogous to the VADER fix recommendation: if `build_updated_stake_reward` cannot locate/update the target stake account, persist the pending reward amount to a durable, separately claimable location (e.g., an account created/refreshed by the runtime, or a rewards-owed ledger keyed by pubkey) instead of unconditionally burning it, so that a staker who withdrew mid-distribution can still later claim what was already computed as owed to them.

### Proof of Concept
1. Wait for the epoch boundary so `begin_partitioned_rewards` computes and locks in a staking reward for account `S` using its balance/delegation at that block [1](#0-0) .
2. `S`'s partition index (determined by `hash_rewards_into_partitions`) falls several blocks later in the distribution window.
3. Before that block height is reached, the staker submits `DeactivateStake` then `WithdrawStake` for the full balance of `S`, removing it from `StakesCache` (standard, unprivileged CLI flow as exercised in `cli/tests/stake.rs`) [5](#0-4) .
4. When the bank reaches `S`'s assigned partition block, `store_stake_accounts_in_partition` calls `build_updated_stake_reward`, which returns `DistributionError::AccountNotFound` because `stakes_cache_accounts.get(&stake_pubkey)` is `None` [7](#0-6) .
5. The previously-computed reward for `S` is added to `stake_reward_lamports_burned` and is never paid to the staker [6](#0-5) , permanently losing the earned reward with no path to reclaim it.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L241-274)
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

        let slot = self.slot();
        let distribution_starting_block_height =
            self.block_height() + REWARD_CALCULATION_NUM_BLOCKS;

        let PartitionedRewardsCalculation {
            stake_rewards,
            point_value,
            ..
        } = rewards_calculation;

        let stake_rewards = Arc::clone(&stake_rewards.stake_rewards);

        let num_partitions = self.get_reward_distribution_num_blocks(&stake_rewards);
        self.set_epoch_reward_status_calculation(distribution_starting_block_height, stake_rewards);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L173-224)
```rust
    /// Process reward credits for a partition of rewards
    /// Store the rewards to AccountsDB, update reward history record and total capitalization.
    fn distribute_epoch_rewards_in_partition(
        &self,
        partition_rewards: &StartBlockHeightAndPartitionedRewards,
        partition_index: u64,
    ) {
        let pre_capitalization = self.capitalization();
        let (
            DistributionResults {
                stake_reward_lamports_minted,
                stake_reward_lamports_burned,
                block_reward_lamports_distributed,
                block_reward_lamports_burned,
                updated_stake_rewards,
            },
            store_stake_accounts_us,
        ) = measure_us!(self.store_stake_accounts_in_partition(partition_rewards, partition_index));

        // increase total capitalization by the distributed rewards
        self.capitalization
            .fetch_add(stake_reward_lamports_minted, Relaxed);

        // decrease total capitalization by burned block rewards
        self.capitalization
            .fetch_sub(block_reward_lamports_burned, Relaxed);

        // decrease distributed capital from epoch rewards sysvar
        self.update_epoch_rewards_sysvar(
            stake_reward_lamports_minted + stake_reward_lamports_burned,
            block_reward_lamports_distributed + block_reward_lamports_burned,
        );

        // update reward history for this partitioned distribution
        self.update_reward_history_in_partition(&updated_stake_rewards);

        let metrics = RewardsStoreMetrics {
            pre_capitalization,
            post_capitalization: self.capitalization(),
            total_stake_accounts_count: partition_rewards.all_stake_rewards.num_rewards(),
            total_num_partitions: partition_rewards.partition_indices.len(),
            partition_index,
            store_stake_accounts_us,
            store_stake_accounts_count: updated_stake_rewards.len(),
            distributed_rewards: stake_reward_lamports_minted,
            burned_rewards: stake_reward_lamports_burned,
            distributed_block_rewards: block_reward_lamports_distributed,
            burned_block_rewards: block_reward_lamports_burned,
        };

        report_partitioned_reward_metrics(self, metrics);
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L239-252)
```rust
    fn build_updated_stake_reward(
        distribution_epoch: u64,
        stake_history: &StakeHistory,
        new_warmup_cooldown_rate_epoch: Option<Epoch>,
        stakes_cache_accounts: &imbl::HashMap<Pubkey, StakeAccount<Delegation>>,
        partitioned_stake_reward: &PartitionedStakeReward,
        rent: &Rent,
        adjust_delegations_for_rent: bool,
        use_fixed_point_stake_math: bool,
    ) -> Result<StakeReward, DistributionError> {
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();
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

**File:** cli/tests/stake.rs (L610-645)
```rust
    // Deactivate stake
    config_validator.command = CliCommand::DeactivateStake {
        stake_account_pubkey: stake_keypair.pubkey(),
        stake_authority: 0,
        sign_only: false,
        deactivate_delinquent: false,
        dump_transaction_message: false,
        blockhash_query: BlockhashQuery::default(),
        nonce_account: None,
        nonce_authority: 0,
        memo: None,
        seed: None,
        fee_payer: 0,
        compute_unit_price: None,
    };
    process_command(&config_validator).await.unwrap();

    // Withdraw stake
    config_validator.signers = vec![&validator_keypair];
    config_validator.command = CliCommand::WithdrawStake {
        stake_account_pubkey: stake_keypair.pubkey(),
        destination_account_pubkey: recipient_pubkey,
        amount: SpendAmount::All,
        withdraw_authority: 0,
        custodian: None,
        sign_only: false,
        dump_transaction_message: false,
        blockhash_query: BlockhashQuery::Rpc(Source::Cluster),
        nonce_authority: 0,
        nonce_account: None,
        memo: None,
        seed: None,
        fee_payer: 0,
        compute_unit_price: None,
    };
    process_command(&config_validator).await.unwrap();
```
