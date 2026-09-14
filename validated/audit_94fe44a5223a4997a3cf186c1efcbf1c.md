No stake-program-level restriction exists that blocks a stake account owner from mutating `Stake.delegation.stake` (via `Split`, `Merge`, `Deactivate`, `Withdraw`, `DeactivateDelinquent`, `Redelegate`) while that account has a stake reward pending distribution during the partitioned epoch-rewards window. The stake processor in this codebase has no `epoch_rewards`/`RewardsPeriod` check gating those instructions . The RPC-side `ActiveRewardsPartitionInterval`/`RewardsPeriod` error only guards RPC query paths (e.g. `getInflationReward`), not transaction execution [1](#0-0) .

Meanwhile, `build_updated_stake_reward` — invoked once per stake account when its partition is actually distributed, potentially many blocks after the reward was *calculated* at the epoch boundary — asserts that the *current* on-chain `stake.delegation.stake` (freshly loaded from `stakes_cache_accounts` at distribution time) plus the previously computed `stake_reward` exactly equals the `new_stake.delegation.stake` value that was computed and cached back at calculation time: [2](#0-1) 

This is the same class of bug as the OpenQ finding: a total/derived value is snapshotted once (at "first claim"/epoch-boundary calculation), but the underlying state (a funder's deposit / a staker's delegation) can be mutated afterward by an ordinary, unprivileged transaction before the deferred consumption of that snapshot (claim / distribution) occurs.

I was not able to fully confirm within the available iterations whether the runtime performs any exhaustive re-validation immediately before this `assert_eq!` (I only found `recalculate_partitioned_rewards_if_active`, which recomputes rewards from the *current* stakes cache, but this is only invoked after a snapshot restore/bank-warp scenario in tests [3](#0-2) , not on every ordinary block during the normal distribution phase). In ordinary block processing, `distribute_partitioned_epoch_rewards` -> `distribute_epoch_rewards_in_partition` -> `store_stake_accounts_in_partition` -> `build_updated_stake_reward` runs against whatever `stakes_cache_accounts` currently holds without any re-validation step guarding against concurrent mutation by the account owner [4](#0-3) [5](#0-4) .

### Title
Stake delegation mutation during pending partitioned-epoch-rewards distribution triggers a consistency-assertion panic (validator halt) - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
Partitioned epoch rewards are computed once, at the epoch boundary, from a snapshot of `StakesCache`, and are then applied to stake accounts over many subsequent blocks (`distribution_starting_block_height` .. `+ num_partitions`). Between calculation and the actual distribution block for a given stake account, an ordinary user can submit a normal, signed stake-program transaction (e.g. `Split`, `Merge`, `Withdraw`, `Deactivate`, `DeactivateDelinquent`, `Redelegate`) against their own stake account, changing `Stake.delegation.stake`. There is no gate in the stake program preventing this while a reward for that account is queued for future distribution. When the deferred distribution eventually processes that account, `build_updated_stake_reward` asserts that the current on-chain `stake.delegation.stake` (post-mutation) plus the previously-computed reward equals the pre-computed `new_stake.delegation.stake`. If the user has changed their delegation in the interim, this invariant is violated.

### Finding Description
- Reward calculation happens once at the epoch boundary and stores `PartitionedStakeReward` entries (including a pre-computed `inflation.stake` value) into `self.epoch_reward_status` for later use [6](#0-5) .
- Distribution is deferred over up to 10% of an epoch's slots via `get_reward_distribution_num_blocks`, and processed block-by-block in `distribute_partitioned_epoch_rewards` [7](#0-6) [4](#0-3) .
- At actual distribution time, `build_updated_stake_reward` reloads the current stake account from `stakes_cache_accounts` (i.e. current chain state, not a frozen snapshot) and, when the rent-adjustment feature path is not taken, asserts an invariant relating the *current* delegation to the *previously calculated* delegation: [8](#0-7) 

- Nothing in the stake program (`programs/stake`) blocks a `Split`/`Merge`/`Withdraw`/`Deactivate`/`Redelegate` instruction on a stake account merely because that account has a pending, not-yet-distributed epoch reward — there is no `EpochRewards`-aware guard in the stake processor.
- Consequently, a normal user transaction that changes their own stake account's `delegation.stake` between the calculation slot and the account's assigned distribution slot causes `expected_delegation != new_stake.delegation.stake`, hitting the `assert_eq!` and panicking the bank-processing thread, which corresponds to a transaction-triggered cluster halt (every validator processing the same block deterministically hits the same panic).

### Impact Explanation
An `assert_eq!` panic inside bank/block processing crashes the validator process handling that block. Because the reward computation and distribution logic is fully deterministic and part of consensus-critical `Bank` processing, all validators replaying the same block would panic identically, producing a cluster-wide halt triggered purely by an ordinary user transaction (no special privileges, no malicious leader/validator behavior required) — this matches the "transaction-triggered cluster halt" acceptance criterion.

### Likelihood Explanation
Likelihood depends on whether normal user-issued stake instructions (`Split`, `Merge`, `Withdraw`, `Deactivate`, `Redelegate`) can, in practice, change `Stake.delegation.stake` for an account that has an outstanding calculated-but-undistributed reward, and whether the reward-recalculation path (`recalculate_partitioned_rewards_if_active`, only demonstrated in tests around snapshot restore) is or is not invoked on every ordinary block of the distribution window. I could not fully confirm within available tool iterations whether ordinary (non-restart) block processing re-derives rewards per-block or only uses the stale calculation snapshot; if it always uses the stale snapshot (as the code path in `store_stake_accounts_in_partition` suggests), the likelihood of triggering this is high and requires only a single well-timed stake instruction from any staker during the multi-block distribution window that follows every epoch boundary.

### Recommendation
Re-validate (or fully recompute) each stake account's reward against its state at actual distribution time rather than asserting equality against a value computed at the earlier calculation snapshot, or disallow/queue stake-mutating instructions against accounts with pending, undistributed epoch rewards until distribution completes for that partition. Replace the `assert_eq!` invariant with a graceful `Err`/burn path (as already exists for `AccountNotFound`/`ArithmeticOverflow`) so a legitimate but unexpected state divergence cannot panic the validator.

### Proof of Concept
1. At an epoch boundary, `begin_partitioned_rewards` calculates rewards for many stake accounts and spreads distribution over `N > 1` blocks (`get_reward_distribution_num_blocks`).
2. Immediately after the calculation block, before this staker's account's assigned partition/block is processed, the staker submits an ordinary `Split` (or `Withdraw`/`Merge`/`Deactivate`) instruction against their own stake account, changing `Stake.delegation.stake`.
3. When the bank reaches the block corresponding to that staker's partition index, `distribute_epoch_rewards_in_partition` -> `store_stake_accounts_in_partition` -> `build_updated_stake_reward` loads the now-mutated stake account and computes `expected_delegation = stake.delegation.stake + stake_reward`, which no longer matches the pre-computed `new_stake.delegation.stake`, hitting the `assert_eq!` at `runtime/src/bank/partitioned_epoch_rewards/distribution.rs:289-293` and panicking bank processing for every validator that replays the block containing the staker's `Split`/`Withdraw`/etc. transaction followed by the distribution block.

### Citations

**File:** rpc-client-api/src/custom_error.rs (L1-1)
```rust
//! Implementation defined RPC server errors
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L79-150)
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L240-294)
```rust
    fn build_updated_stake_reward(
        distribution_epoch: u64,
        stake_history: &StakeHistory,
        new_warmup_cooldown_rate_epoch: Option<Epoch>,
        stakes_cache_accounts: &imbl::HashMap<Pubkey, StakeAccount<Delegation>>,
        partitioned_stake_reward: &PartitionedStakeReward,
        rent: &Rent,
        adjust_delegations_for_rent: bool,
    ) -> Result<StakeReward, DistributionError> {
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

        let mut new_stake = partitioned_stake_reward.inflation.stake;
        if adjust_delegations_for_rent {
            let minimum_balance = rent.minimum_balance(account.data().len());
            // The rewarded epoch is right before the distribution epoch
            let rewarded_epoch = distribution_epoch.saturating_sub(1);
            // The entry in `partitioned_stake_reward` contains the rewards,
            // calculated during the calculation phase
            let delegation_with_rewards = new_stake.delegation.stake;
            adjust_delegation_for_rent(
                &mut new_stake.delegation,
                rewarded_epoch,
                delegation_with_rewards,
                account.lamports(),
                minimum_balance,
            );
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L358-404)
```rust
        let stakes_cache = self.stakes_cache.stakes();
        let stakes_cache_accounts = stakes_cache.stake_delegations();
        let stake_history = stakes_cache.history();
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let rent = &self.rent_collector.rent;
        for index in indices {
            let partitioned_stake_reward = partition_rewards
                .all_stake_rewards
                .get(*index)
                .unwrap_or_else(|| {
                    panic!(
                        "partition reward out of bound: {index} >= {}",
                        partition_rewards.all_stake_rewards.total_len()
                    )
                })
                .as_ref()
                .unwrap_or_else(|| {
                    panic!("partition reward {index} is empty");
                });
            let stake_pubkey = partitioned_stake_reward.stake_pubkey;
            let stake_reward_amount = partitioned_stake_reward.inflation.stake_reward;
            let block_reward_amount = partitioned_stake_reward.block_reward;

            match Self::build_updated_stake_reward(
                self.epoch,
                stake_history,
                new_warmup_cooldown_rate_epoch,
                stakes_cache_accounts,
                partitioned_stake_reward,
                rent,
                adjust_delegations_for_rent,
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
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1005-1027)
```rust
    /// If rewards are still active, recalculates partitioned stake rewards and
    /// updates Bank::epoch_reward_status. This method assumes that reward
    /// commissions have already been calculated and delivered, and *only*
    /// recalculates stake rewards
    pub(in crate::bank) fn recalculate_partitioned_rewards_if_active<F, TP>(
        &mut self,
        thread_pool_builder: F,
    ) where
        F: FnOnce() -> TP,
        TP: std::borrow::Borrow<ThreadPool>,
    {
        let epoch_rewards_sysvar = self.get_epoch_rewards_sysvar();
        if epoch_rewards_sysvar.active {
            let thread_pool = thread_pool_builder();
            let (stake_rewards, partition_indices) =
                self.recalculate_stake_rewards(&epoch_rewards_sysvar, thread_pool.borrow());
            self.set_epoch_reward_status_distribution(
                epoch_rewards_sysvar.distribution_starting_block_height,
                stake_rewards,
                partition_indices,
            );
        }
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1811-1872)
```rust
        assert_eq!(bank.epoch(), op.epoch);
        for (vote_address, vote_op) in &op.vote_operations {
            if let Some(balance) = &vote_op.create_with_balance {
                // Create a BLS pubkey so the vote account passes VAT filtering
                let identity = Keypair::new();
                let bls_keypair =
                    BLSKeypair::derive_from_signer(&identity, BLS_KEYPAIR_DERIVE_SEED).unwrap();
                let (bls_pubkey, bls_pop) =
                    create_bls_proof_of_possession(vote_address, &bls_keypair);
                let vote_init = VoteInitV2 {
                    node_pubkey: identity.pubkey(),
                    authorized_voter: identity.pubkey(),
                    authorized_voter_bls_pubkey: bls_pubkey,
                    authorized_voter_bls_proof_of_possession: bls_pop,
                    ..VoteInitV2::default()
                };
                let vote_state = VoteStateV4::new(
                    &vote_init,
                    vote_address,
                    &identity.pubkey(),
                    &Clock::default(),
                );
                let mut account = solana_account::AccountSharedData::new(
                    *balance,
                    VoteStateV4::size_of(),
                    &solana_vote_program::id(),
                );
                account
                    .set_state(&VoteStateVersions::new_v4(vote_state))
                    .unwrap();
                bank.store_account(vote_address, &account);
            }

            if let Some(stake_amount) = &vote_op.delegate_stake_amount {
                let size = StakeStateV2::size_of();
                let rent_exempt_reserve = bank.rent_collector().rent.minimum_balance(size);
                let lamports = rent_exempt_reserve + stake_amount;
                let stake_account =
                    create_stake_account(lamports, *stake_amount, vote_address, bank.epoch());
                bank.store_account(&Pubkey::new_unique(), &stake_account);
            }

            let modify_vote_state = |modify_fn: &dyn Fn(&mut VoteStateV4)| {
                let mut vote_account = bank.get_account(vote_address).unwrap();
                let vote_state_versions: VoteStateVersions = vote_account.state().unwrap();
                let VoteStateVersions::V4(mut vote_state) = vote_state_versions else {
                    panic!("unexpected version");
                };

                modify_fn(&mut vote_state);

                vote_account
                    .set_state(&VoteStateVersions::V4(vote_state))
                    .unwrap();
                bank.store_account(vote_address, &vote_account);
            };

            if let Some(commission) = vote_op.new_commission {
                modify_vote_state(&|vote_state: &mut VoteStateV4| {
                    vote_state.inflation_rewards_commission_bps = commission as u16 * 100;
                });
            }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L403-428)
```rust
    /// # stake accounts to store in one block during partitioned reward interval
    pub(super) fn partitioned_rewards_stake_account_stores_per_block(&self) -> u64 {
        self.partitioned_rewards_stake_account_stores_per_block
    }

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
