### Title
Stake withdrawal between reward calculation and partitioned distribution permanently burns the staker's already-computed reward - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
Solana's partitioned epoch-rewards mechanism computes each stake account's reward once, at the epoch boundary, and then pays it out over many subsequent blocks (one partition per block). Between the calculation block and the block that actually credits a given account, the account's owner (the withdraw authority — an ordinary, unprivileged user, not a validator/operator) can submit a normal `Withdraw` stake instruction that fully empties and closes the account. When the account's turn to be paid arrives, the distribution code cannot find it in the `StakesCache` any more and, instead of preserving or re-attributing the reward, silently discards ("burns") it — exactly analogous to the Etherfi report's pattern of a request being invalidated after being queued, with the "debt" (here, the computed reward) never being honored.

### Finding Description
Reward calculation happens once at the epoch boundary and stores a `PartitionedStakeRewards` list keyed by stake pubkey [1](#0-0) . Distribution is spread over several following blocks, one partition per block [2](#0-1) .

When a partition is finally processed, `build_updated_stake_reward` looks the stake account up in the current `StakesCache` snapshot and requires it to exist: [3](#0-2) 

If the account is not found (i.e., it was fully withdrawn/closed after calculation but before this block's distribution), `store_stake_accounts_in_partition` treats this as an error and burns the reward instead of crediting anyone: [4](#0-3) 

The code's own comment acknowledges the assumption this relies on and treats the burn path as something that "should never" happen because "further state mutation [is] prevent[ed] by stake-program restrictions": [5](#0-4) 

However, no such restriction exists in the stake program or bank code that blocks a `Withdraw` instruction from a stake account's own (unprivileged) withdraw authority during the reward-interval window. A stake account that deactivated in the rewarded epoch can have zero effective/activating/deactivating stake as soon as the new epoch's `StakeHistory` entry is recognized (which happens at the very start of the new epoch, before or concurrently with reward calculation for a small enough deactivating amount relative to the pool). Its withdraw authority can then submit an ordinary `Withdraw` for the full balance in any of the (potentially many) blocks between the calculation block and their partition's distribution block, closing the account (changing it from `StakeStateV2::Stake` to `StakeStateV2::Uninitialized`) and removing it from `stakes_cache.stake_delegations()`. The already-computed, previously-locked-in reward for that account then hits the `AccountNotFound` branch and is silently burned rather than delivered to (or refunded to) the account or its owner.

This mirrors the reported bug class precisely: a request/obligation is computed and queued (the withdrawal request / the calculated reward), an unprivileged actor performs a normal, permitted action (`Withdraw`) that invalidates the target of that obligation, and the system has no mechanism to redirect or preserve the value — it is simply lost, contradicting the code's own invariant that this "should never" occur.

### Impact Explanation
The affected reward's lamports are subtracted from `stake_reward_lamports_minted`/added to `stake_reward_lamports_burned`, meaning the value is never actually credited to capitalization for that reward, silently diverging total distributed rewards from the value recorded as `total_rewards`/`total_points` in the `EpochRewards` sysvar for that epoch. This breaks the invariant the code itself documents ("there should never be rewards burned"), producing an unaccounted-for discrepancy between the amount the protocol calculated it owed and the amount it actually paid out for the epoch — value is effectively destroyed rather than distributed as designed.

### Likelihood Explanation
Triggering this requires only an ordinary `Withdraw` stake instruction from the account's own withdraw authority — no special role or permission — timed to land between the epoch-boundary calculation block and the block responsible for that account's partition. Because full-epoch distribution can span many blocks (one per partition, up to a meaningful fraction of an epoch in the worst case), and a small/fully-cooled-down deactivating stake can become fully withdrawable as soon as the epoch turns over, this window is realistically reachable by any staker who deactivates shortly before an epoch boundary.

### Recommendation
Do not treat a missing stake account during distribution as pure loss. Either (a) prevent full-balance withdrawal of a stake account that still has an outstanding, uncredited partitioned reward (e.g., track "pending reward" obligations and enforce a minimum balance/refuse the withdrawal), or (b) redirect an orphaned reward's lamports to a recoverable location (e.g., credit them to the withdraw destination/authority, or route them back into the rewards pool/capitalization accounting explicitly) instead of silently burning them, and update `update_epoch_rewards_sysvar`/capitalization bookkeeping to reflect this deterministically rather than relying on an assumption that the condition is unreachable.

### Proof of Concept
1. Create and delegate a small stake account such that, at the start of epoch N+1, its deactivation (initiated in epoch N) is already fully complete in the new epoch's `StakeHistory` entry (effective/activating/deactivating all 0).
2. At the epoch boundary, `Bank::new_from_parent` computes and caches the partitioned reward for this account for epoch N (per `calculate_stake_rewards_and_commissions`), including it in `EpochRewardPhase::Calculation`/`Distribution` state [6](#0-5) .
3. Before the block whose `partition_index` contains this account's reward is processed, submit an ordinary `Withdraw` instruction from the account's withdraw authority for the full account balance, closing the stake account (`StakeStateV2::Uninitialized`), removing it from `stakes_cache.stake_delegations()`.
4. When `store_stake_accounts_in_partition` reaches this account's `PartitionedStakeReward`, `build_updated_stake_reward` returns `Err(DistributionError::AccountNotFound)` [3](#0-2) , and the reward amount is added to `stake_reward_lamports_burned` instead of being paid [7](#0-6) , confirming the reward is permanently lost rather than distributed.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L79-112)
```rust
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L137-149)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L384-407)
```rust
            match Self::build_updated_stake_reward(
                self.epoch,
                stake_history,
                new_warmup_cooldown_rate_epoch,
                stakes_cache_accounts,
                partitioned_stake_reward,
                rent,
                adjust_delegations_for_rent,
                use_fixed_point_stake_math,
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
