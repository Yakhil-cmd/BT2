### Title
Staker's Fully-Accrued Epoch Reward Is Permanently Burned If The Stake Account Is Withdrawn Before Its Partition Is Distributed - (File: `runtime/src/bank/partitioned_epoch_rewards/distribution.rs`)

### Summary
Partitioned epoch rewards are calculated once at the epoch boundary but paid out to stake accounts over many subsequent blocks (up to 10% of an epoch's slots). If a stake account that was included in the reward calculation is closed (fully withdrawn) by its own owner before its partition's distribution block arrives, the corresponding reward is not paid to anyone — it is silently discarded ("burned") when the distribution code cannot find the account. This mirrors the referenced report's core bug class: a normal, permissionless account-closing action that races a delayed, multi-block reward-crediting process, causing the owner to permanently lose an already-computed reward.

### Finding Description
`store_stake_accounts_in_partition` looks up each `partitioned_stake_reward.stake_pubkey` in the *current* `StakesCache` at the time its partition block is processed, not the state at calculation time: [1](#0-0) 

If the account can't be found, `build_updated_stake_reward` returns `DistributionError::AccountNotFound`, and the caller `store_stake_accounts_in_partition` counts that reward as burned instead of paid: [2](#0-1) 

The burned lamports are then explicitly subtracted from `capitalization`, i.e. minted-then-destroyed rather than delivered to the staker: [3](#0-2) 

The code's own comment assumes this path is unreachable in practice ("stake accounts are checked in calculation, and further state mutation prevents by stake-program restrictions, there should never be rewards burned"): [4](#0-3) 

However, distribution can legitimately span many blocks after calculation — up to `slots_per_epoch / 10`: [5](#0-4) 

A delegation that finished deactivating in the rewarded epoch is explicitly expected by this same code to have zero effective stake by distribution time (`RewardType::DeactivatedStake`), and it still receives a reward for that already-completed rewarded epoch: [6](#0-5) 

Once a delegation's effective stake is 0, the stake program's `Withdraw` instruction permits withdrawing the account's entire balance (as demonstrated in the CLI test, once stake is fully deactivated/inactive, "Complete balance is withdrawn"): [7](#0-6) 

Nothing in `distribute_partitioned_epoch_rewards`/`EpochRewardStatus` blocks a normal `Withdraw`/close instruction from executing while a stake account's reward is still pending in a later partition — `EpochRewardStatus` is purely a bank-internal scheduling flag consulted by the rewards-distribution code itself, not by the stake program's instruction processor: [8](#0-7) [9](#0-8) 

I was unable to locate the stake program's instruction-processor source (`programs/stake*`) in the indexed codebase to directly confirm the absence of any block on withdrawing a stake account whose reward is still queued for a later partition; this may be due to index size limits. The CLI end-to-end test cited above is the strongest available evidence that a fully-deactivated stake account's entire balance becomes withdrawable as soon as its effective stake reaches zero, without regard to pending, not-yet-distributed rewards.

### Impact Explanation
An unprivileged staker who deactivates and (immediately once the deactivation cooldown completes) withdraws their entire stake account before their reward partition is processed loses their already-computed and cryptographically-committed epoch reward. The lamports are minted into the epoch-rewards sysvar accounting and then explicitly burned from capitalization rather than delivered, permanently destroying value owed to the user. This is analogous to the referenced Concur bug where a legitimate, delayed, multi-step reward-distribution mechanism raced against a normal account-draining action, causing loss of yield that could never be recovered.

### Likelihood Explanation
This requires only ordinary, unprivileged actions (`DeactivateStake` followed by `Withdraw`) timed to land after the reward-calculation block but before the specific block that processes that account's partition — a window that can span up to `slots_per_epoch / 10` blocks per the reward-distribution scheduling logic. No validator/operator privilege, malicious snapshot, or multi-client coordination is required, only knowledge of which partition/block a given stake pubkey hashes into (computed deterministically from `parent_blockhash`), which is derivable off-chain before submitting the withdraw transaction.

### Recommendation
Before permitting a stake account to be fully withdrawn/closed, check the bank's `EpochRewardStatus` and refuse (or defer) `Withdraw` for stake accounts (or reward pubkeys) that have already been counted in an active-but-undistributed `PartitionedStakeRewards` set, until their partition has been processed. Alternatively, credit computed-but-undeliverable rewards to an unclaimed-rewards pool or the destination of the withdraw rather than silently burning them from capitalization.

### Proof of Concept
1. At an epoch boundary, a stake account with a `deactivation_epoch` equal to the just-completed rewarded epoch is included in `PartitionedStakeRewards` (per `build_updated_stake_reward`'s `RewardType::DeactivatedStake` branch) and hashed into a later partition index via `hash_rewards_into_partitions`.
2. Immediately after the calculation block, the owner submits `DeactivateStake`-completed / `Withdraw` for the full balance (permitted once effective stake is 0, as shown in `test_stake_delegation_and_withdraw_available` at `cli/tests/stake.rs:440-477`), closing the account before its partition block arrives.
3. When `distribute_epoch_rewards_in_partition` later processes that partition, `build_updated_stake_reward` fails to find the account (`DistributionError::AccountNotFound`) and `store_stake_accounts_in_partition` records the reward as `stake_reward_lamports_burned`, which `distribute_epoch_rewards_in_partition` subtracts from capitalization instead of paying the owner.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L78-93)
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L192-204)
```rust
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-252)
```rust
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L299-310)
```rust
        let stake_at_distribution_epoch = delegation_effective_stake(
            &new_stake.delegation,
            distribution_epoch,
            stake_history,
            new_warmup_cooldown_rate_epoch,
            use_fixed_point_stake_math,
        );
        let reward_type = if stake_at_distribution_epoch == 0 {
            RewardType::DeactivatedStake
        } else {
            RewardType::Staking
        };
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

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L160-171)
```rust
/// Represent whether bank is in the reward phase or not.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) enum EpochRewardStatus {
    /// this bank is in the reward phase.
    /// Contents are the start point for epoch reward calculation,
    /// i.e. parent_slot and parent_block height for the starting
    /// block of the current epoch.
    Active(EpochRewardPhase),
    /// this bank is outside of the rewarding phase.
    #[default]
    Inactive,
}
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

**File:** cli/tests/stake.rs (L440-477)
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

    // Withdraw available stake
    config_validator.signers = vec![&validator_keypair];
    config_validator.command = CliCommand::WithdrawStake {
        stake_account_pubkey: stake_keypair.pubkey(),
        destination_account_pubkey: recipient_pubkey,
        amount: SpendAmount::Available,
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
    // Complete balance is withdrawn because all stake is inactive
    check_balance!(55 * LAMPORTS_PER_SOL, &rpc_client, &recipient_pubkey);
```
