## Title
Legitimately-earned stake rewards are silently burned when a stake account is closed/withdrawn between epoch-reward calculation and distribution - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

## Summary
The Kodiak report describes rewards becoming unclaimable because the payout path can revert/fail after the reward amount has already been "earned" but before it is actually transferred, and the code offers no fallback other than reverting the whole operation. The Agave analog is in the partitioned epoch-rewards distribution pipeline: a stake reward is calculated and fixed into `all_stake_rewards`/`EpochRewards.total_rewards` at the epoch boundary, but is only actually credited to the stake account several blocks later, during `distribute_epoch_rewards_in_partition`. If, in the intervening blocks, the stake authority withdraws/closes the stake account (a fully legitimate, unprivileged action once stake is inactive), the account disappears from `StakesCache`, and `build_updated_stake_reward` returns `DistributionError::AccountNotFound`. The caller treats this as a normal "burn" path rather than a safety violation.

## Finding Description
Reward calculation happens once, at the epoch boundary, and produces `PartitionedStakeReward` entries that are hashed into partitions and distributed one partition per block over many subsequent blocks [1](#0-0) . The rewards are fixed at calculation time and recorded into `EpochRewards.total_rewards`, so they are accounted for in the epoch's total lamport supply before any of them are individually credited to accounts [2](#0-1) .

Actual crediting happens later, per-partition, in `store_stake_accounts_in_partition`, which looks up the stake account from the *current* `StakesCache` (not a snapshot) via `build_updated_stake_reward`: [3](#0-2) 

If the pubkey is no longer present as a delegated stake account in `stakes_cache_accounts` (e.g. because the stake was withdrawn to zero and the account was reassigned/closed, which removes it from `stake_delegations` via `remove_stake_delegation`), the lookup fails with `DistributionError::AccountNotFound` [4](#0-3) [5](#0-4) .

The caller does not retry, redirect, or otherwise safely handle this failure — it silently converts the reward into a "burned" reward and moves on: [6](#0-5) 

The function's own doc comment acknowledges this is not supposed to be reachable: *"Because stake accounts are checked in calculation, and further state mutation prevents by stake-program restrictions, there should never be rewards burned."* [7](#0-6)  — i.e. the design assumes the stake-program instruction handlers (`Withdraw`, `Deactivate`, etc.) will prevent an account with a pending/undelivered epoch reward from being closed during the multi-block distribution window. Unlike the vote program, which explicitly protects `pending_delegator_rewards` from being withdrawn below the reserved amount [8](#0-7) , no equivalent guard was found for stake accounts in the reviewed code paths, and the distribution code itself defensively assumes the "should never happen" case can in fact happen (it has a dedicated `DistributionError::AccountNotFound` variant and burn-accounting branch specifically for it).

This mirrors the Kodiak bug class: an amount is "earned"/reserved on one side of an asynchronous, multi-step settlement, but the actual payout leg can fail due to a state change made by the very user entitled to the funds, and the fallback behavior (burn) permanently forfeits the reward instead of safely redirecting or re-queuing it.

## Impact Explanation
When triggered, a staker's already-calculated inflation reward for the previous epoch is permanently lost: `stake_reward_lamports_burned` is incremented and the lamports are never minted/credited to any account, while `EpochRewards.distributed_rewards` still advances as if it were paid [9](#0-8) [10](#0-9) . This is a concrete, unrecoverable loss of a legitimately earned lamport reward for an ordinary staker action (deactivate + withdraw), which is a different but comparably severe outcome than the "stuck funds" described in the Kodiak report — instead of funds sitting inaccessible in an intermediary, here they are destroyed outright with no path to recovery.

## Likelihood Explanation
The reward-distribution window spans multiple blocks after the epoch boundary (`REWARD_CALCULATION_NUM_BLOCKS` plus one block per partition) [11](#0-10) , giving an ordinary staker a realistic window to submit a `Withdraw` for a fully-deactivated stake account before their partition is processed. This requires no special privilege — only that the staker has already deactivated stake from a prior epoch and withdraws it during this window, which is a completely normal, unprivileged CLI operation exposed via `withdraw-stake` [12](#0-11) .

I was not able to fully confirm within the available index whether the stake program instruction handlers (`programs/stake-*` crates) contain a check that blocks withdrawal of a stake account while an epoch-reward payout for it is still pending in the active `EpochRewardStatus`/`EpochRewards` sysvar (analogous to the vote program's `pending_delegator_rewards` guard). No such check was found in the indexed code, and the `distribution.rs` comment's phrasing ("further state mutation prevents by stake-program restrictions") implies the authors believe such a restriction exists elsewhere, but I could not locate or verify it directly. This should be confirmed by a Devin session with full repository access before treating likelihood as fully validated.

## Recommendation
Two complementary fixes, mirroring the Kodiak report's approach of (a) not letting an isolated failure destroy funds, and (b) closing the loop that lets funds land somewhere unintended:
1. In `store_stake_accounts_in_partition`, when `build_updated_stake_reward` returns `AccountNotFound`, do not burn the reward silently. Instead redirect the un-deliverable reward lamports to a safe destination (e.g. credit the original stake authority/withdraw destination if recoverable from the closed account's prior state, or route to a well-defined recovery/incinerator path with clear, auditable accounting) rather than quietly vanishing them from the reported "distributed" total.
2. Add an explicit guard in the stake program's `Withdraw`/close paths (and any other user-triggerable removal of a `StakeStateV2::Stake` account from `StakesCache`) that rejects the instruction, or defers the removal, while an epoch reward for that stake pubkey is still pending in the active `EpochRewardStatus::Distribution` phase — analogous to the vote program's `pending_delegator_rewards` reservation check.

## Proof of Concept
1. At an epoch boundary, a staker's stake account (already deactivated in a prior epoch, so it is eligible for a nonzero `stake_reward` under `redeem_delegation_rewards`) is included in `calculate_stake_rewards_and_commissions`, producing a `PartitionedStakeReward` and increasing `EpochRewards.total_rewards` accordingly [13](#0-12) .
2. `begin_partitioned_rewards` schedules distribution across `num_partitions` future blocks, entering `EpochRewardPhase::Distribution` [1](#0-0) .
3. Before the block corresponding to this staker's partition is processed, the staker submits `StakeInstruction::Withdraw` for the full (inactive) balance of the stake account, which is a standard, unprivileged CLI action [14](#0-13) , removing the delegation from `StakesCache` via `remove_stake_delegation` [5](#0-4) .
4. When the scheduled partition block arrives, `store_stake_accounts_in_partition` looks up the stake pubkey in `stakes_cache_accounts`, fails to find it, and `build_updated_stake_reward` returns `DistributionError::AccountNotFound` [4](#0-3) .
5. The reward is added to `stake_reward_lamports_burned` instead of being minted to any account [9](#0-8) , and `EpochRewards.distributed_rewards` is advanced as if paid [10](#0-9)  — the staker's already-earned reward is permanently and silently lost.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L80-149)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L261-292)
```rust
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

        self.create_epoch_rewards_sysvar(
            distributed_lamports + distributed_to_incinerator_lamports + burned_lamports,
            distribution_starting_block_height,
            num_partitions,
            point_value,
            0, // block_rewards
        );

        datapoint_info!(
            "epoch-rewards-status-update",
            ("start_slot", slot, i64),
            ("calculation_block_height", self.block_height(), i64),
            ("active", 1, i64),
            ("parent_slot", parent_slot, i64),
            ("parent_block_height", parent_block_height, i64),
        );
        distributed_lamports
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L820-871)
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
```

**File:** runtime/src/stakes.rs (L582-601)
```rust
    fn remove_stake_delegation(
        &mut self,
        stake_pubkey: &Pubkey,
        new_rate_activation_epoch: Option<Epoch>,
        use_fixed_point_stake_math: bool,
    ) {
        if let Some(stake_account) = self.stake_delegations.remove(stake_pubkey) {
            let removed_delegation = stake_account.delegation();
            let removed_stake = delegation_effective_stake(
                removed_delegation,
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
                use_fixed_point_stake_math,
            );
            self.sub_delegated_stake(&removed_delegation.voter_pubkey, removed_stake);
            self.vote_accounts
                .sub_stake(&removed_delegation.voter_pubkey, removed_stake);
        }
    }
```

**File:** programs/vote/src/vote_processor.rs (L5264-5282)
```rust
        // Should fail, can't close vote account when
        // pending_delegator_rewards > 0.
        process_instruction(
            features,
            &serialize(&VoteInstruction::Withdraw(vote_account_lamports)).unwrap(),
            transaction_accounts.clone(),
            instruction_accounts.clone(),
            Err(InstructionError::InsufficientFunds),
        );

        // Should fail, can't withdraw more than
        // (lamports - pending_delegator_rewards - rent_exempt).
        process_instruction(
            features,
            &serialize(&VoteInstruction::Withdraw(vote_account_lamports + 1)).unwrap(),
            transaction_accounts.clone(),
            instruction_accounts.clone(),
            Err(InstructionError::InsufficientFunds),
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/sysvar.rs (L74-109)
```rust
    /// Update EpochRewards sysvar with distributed rewards
    pub(in crate::bank::partitioned_epoch_rewards) fn update_epoch_rewards_sysvar(
        &self,
        inflation_reward_lamports_minted_and_burned: u64,
        debit_block_reward_lamports: u64,
    ) {
        let mut epoch_rewards = self.get_epoch_rewards_sysvar();
        assert!(epoch_rewards.active);

        epoch_rewards.distribute(inflation_reward_lamports_minted_and_burned);

        self.update_sysvar_account(&sysvar::epoch_rewards::id(), |account| {
            create_account(
                &epoch_rewards,
                self.inherit_specially_retained_account_fields(account),
            )
        });

        // Debit the lamports separately without updating capitalization,
        // since block reward lamports already existed
        let mut account = self
            .get_account_with_fixed_root(&sysvar::epoch_rewards::id())
            .expect("created sysvar account exists");

        // SAFETY: programmer error if we debit too many block rewards
        account
            .checked_sub_lamports(debit_block_reward_lamports)
            .expect("epoch reward sysvar has enough lamports for distribution");
        assert!(
            account.lamports() >= self.get_minimum_balance_for_rent_exemption(account.data().len()),
            "Sysvar account must have enough for rent exemption after debiting block rewards"
        );
        self.store_account(&sysvar::epoch_rewards::id(), &account);

        self.log_epoch_rewards_sysvar("update");
    }
```

**File:** cli/src/stake.rs (L1877-1895)
```rust
#[allow(clippy::too_many_arguments)]
pub async fn process_withdraw_stake(
    rpc_client: &RpcClient,
    config: &CliConfig<'_>,
    stake_account_pubkey: &Pubkey,
    destination_account_pubkey: &Pubkey,
    amount: SpendAmount,
    withdraw_authority: SignerIndex,
    custodian: Option<SignerIndex>,
    sign_only: bool,
    dump_transaction_message: bool,
    blockhash_query: &BlockhashQuery,
    nonce_account: Option<&Pubkey>,
    nonce_authority: SignerIndex,
    memo: Option<&String>,
    seed: Option<&String>,
    fee_payer: SignerIndex,
    compute_unit_price: Option<u64>,
) -> ProcessResult {
```

**File:** cli/src/stake.rs (L1916-1923)
```rust
    let build_message = |lamports| {
        let ixs = vec![stake_instruction::withdraw(
            &stake_account_address,
            &withdraw_authority.pubkey(),
            destination_account_pubkey,
            lamports,
            custodian.map(|signer| signer.pubkey()).as_ref(),
        )]
```
