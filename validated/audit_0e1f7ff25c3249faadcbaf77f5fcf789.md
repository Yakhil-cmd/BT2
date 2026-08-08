### Title
Merging/topping-up a stake account during partitioned epoch-reward distribution can trigger a consensus-halting `assert_eq!` panic in `build_updated_stake_reward` - (File: `runtime/src/bank/partitioned_epoch_rewards/distribution.rs`)

### Summary
Reward calculation and reward distribution for stake accounts are split into two separate phases that read stake-account state at two different points in time, similar to the `KangarooVault` bug where `premiumCollected` and `performanceFee` were computed from two different, inconsistent snapshots of state. At the epoch boundary, `calculate_stake_rewards_and_commissions` computes a `PartitionedStakeReward` per stake pubkey, embedding a *pre-computed* `new_stake.delegation.stake` value. Several blocks later (one block per partition), `build_updated_stake_reward` re-reads the *current* stake account from `StakesCache` and, when the `relax_post_exec_min_balance_check` feature is inactive, asserts that `current_delegation.stake + stake_reward == precomputed_new_delegation.stake`. Because a stake account's delegated stake can be legitimately changed between calculation and distribution (e.g. via `Merge`), an unprivileged user can invalidate this invariant and cause the assertion to panic during block processing on every validator.

### Finding Description
`calculate_stake_rewards_and_commissions` / `redeem_delegation_rewards` computes, once per epoch, a `PartitionedStakeReward` containing `inflation.stake` — the delegation state *as it will be after adding the reward*, based on the stake account snapshot taken at epoch-boundary calculation time: [1](#0-0) 

This reward set is distributed over multiple subsequent blocks (`num_partitions`), not applied all at once, via `distribute_partitioned_epoch_rewards` → `distribute_epoch_rewards_in_partition` → `store_stake_accounts_in_partition`: [2](#0-1) 

For each partition, `build_updated_stake_reward` re-loads the *current* stake account from `stakes_cache_accounts` (i.e., the live state as of the current distribution block, which reflects any transactions users have submitted in the interim) and adds the reward: [3](#0-2) 

When `adjust_delegations_for_rent` (feature `relax_post_exec_min_balance_check`) is **not** active, the code takes the `else` branch and asserts that the live delegation plus the reward exactly equals the pre-computed delegation value from the calculation phase: [4](#0-3) 

This is precisely the same class of bug as the `KangarooVault` report: one code path (`calculate_stake_rewards_and_commissions`) "prices in" a value (the delegation amount) frozen at one point in time, while a second code path (`store_stake_accounts_in_partition` at actual distribution time) reads a live, mutable value for the same underlying quantity. In `KangarooVault`, a user could call `processWithdraw()` between fee-accrual and fee-deduction to dodge the fee borne by others. Here, a stake-account owner can submit a stake-program instruction (e.g. `Merge`, which is fully permitted between two active stake accounts delegated to the same vote account, and requires only the stake/withdraw authority — no privileged/operator role) that changes `stake.delegation.stake` for their own stake pubkey after epoch-boundary reward calculation, but before that pubkey's `PartitionedStakeReward` entry is applied in its assigned partition several blocks later. When that partition block is processed by every validator (this runs deterministically in block processing, not only locally), `expected_delegation != new_stake.delegation.stake`, and the `assert_eq!` fires, panicking the bank/validator process network-wide at the same slot.

### Impact Explanation
Because `distribute_partitioned_epoch_rewards` executes deterministically as part of normal block processing for the assigned partition slot (not just on the originating node), triggering this assertion causes every validator processing that slot to panic in the same way. This is a network-wide, epoch-boundary halt condition triggerable by an ordinary stake-account holder performing a legitimate stake-program action (`Merge`) during the multi-block reward-distribution window — no elevated privileges or operator role required. This matches the accepted "epoch-boundary halt" impact category.

### Likelihood Explanation
Likelihood depends on whether `relax_post_exec_min_balance_check` is active on the target cluster; if inactive, the `else`/`assert_eq!` branch is live and the window is real: distribution spans `num_partitions` blocks (up to one partition per block for the whole epoch reward set), giving ample time for a user to merge one of their own delegated, active stake accounts with another compatible one before their specific partition is processed. I was not able to verify from the indexed code whether `relax_post_exec_min_balance_check` is already permanently active/cleaned-up on mainnet (i.e., whether the vulnerable `else` branch is dead code in practice); this should be confirmed against the live feature-activation status before treating this as exploitable today.

### Recommendation
Do not assert equality against a value computed from a stale, pre-distribution snapshot of mutable stake-account state. Either:
- Always take the `adjust_delegation_for_rent`-style path (recompute the expected post-reward delegation from the *current* live delegation state at distribution time) unconditionally, removing the strict `assert_eq!` on stale precomputed state, or
- Detect a mismatch between the live delegation and the expected pre-computed delegation and treat it as a recoverable distribution error (burn/skip that reward, as already done for `DistributionError::AccountNotFound`) instead of panicking.

### Proof of Concept
Conceptual reproduction (not executed, given index-only access):
1. On a cluster where feature `relax_post_exec_min_balance_check` is inactive, wait for an epoch boundary; reward calculation runs and produces a `PartitionedStakeReward` for stake account `A` (delegated, active) embedding `A`'s pre-computed post-reward delegation.
2. Before `A`'s assigned partition block is reached (reward distribution spans multiple blocks, `distribution_starting_block_height` to `distribution_end_exclusive` in [5](#0-4) ), submit a `Merge` instruction merging stake account `B` (also active, delegated to the same voter) into `A`, using only `A`/`B`'s stake/withdraw authority (an unprivileged action).
3. When `A`'s partition block is processed, `build_updated_stake_reward` loads the now-merged, larger delegation for `A` and computes `expected_delegation = stake.delegation.stake + stake_reward`, which no longer matches the pre-computed `new_stake.delegation.stake` from step 1, firing the `assert_eq!` at [6](#0-5)  and panicking every validator processing that slot.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L744-757)
```rust
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L137-150)
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-267)
```rust
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();

        let (mut account, stake_state): (AccountSharedData, StakeStateV2) = stake_account.into();
        let StakeStateV2::Stake(meta, stake, flags) = stake_state else {
            // StakesCache only stores accounts where StakeStateV2::delegation().is_some()
            unreachable!(
                "StakesCache entry {:?} failed StakeStateV2 deserialization",
                partitioned_stake_reward.stake_pubkey
            )
        };
        account
            .checked_add_lamports(partitioned_stake_reward.inflation.stake_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
        account
            .checked_add_lamports(partitioned_stake_reward.block_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L284-294)
```rust
        } else {
            let expected_delegation = stake
                .delegation
                .stake
                .saturating_add(partitioned_stake_reward.inflation.stake_reward);
            assert_eq!(
                expected_delegation, new_stake.delegation.stake,
                "stake reward delegation must be consistent with the updated stake account \
                 lamport balance"
            );
        }
```
