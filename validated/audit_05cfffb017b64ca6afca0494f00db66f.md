### Title
Panic-inducing `assert_eq!` on stake delegation consistency during partitioned epoch-reward distribution can halt the validator - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
Partitioned epoch-reward distribution recomputes a stake account's expected post-reward delegation and asserts it matches a value computed earlier during the calculation phase. Because calculation and distribution happen at different points in time (and, for partitioned rewards, across multiple separate blocks/slots), an unprivileged staker's legitimate, ordinary stake instructions executed in that window can change the live delegation/lamports before distribution runs. When `adjust_delegations_for_rent` is `false`, this mismatch is checked with `assert_eq!`, which panics the runtime instead of returning a recoverable error, matching the report's core bug class: a strict equality check comparing a value "frozen" at update/calculation time against a value that can legitimately change before it is consumed at processing/distribution time.

### Finding Description
In `build_updated_stake_reward` [1](#0-0) , the stake account currently in the stakes cache (`stake`, fetched live via `stakes_cache_accounts.get(&partitioned_stake_reward.stake_pubkey)`) is combined with reward data that was computed earlier, during the separate reward-calculation phase (`partitioned_stake_reward.inflation`, produced by `redeem_delegation_rewards` in `calculation.rs`) [2](#0-1) .

When the `relax_post_exec_min_balance_check` feature is not active, `adjust_delegations_for_rent` is `false`, and the function instead does a strict consistency check: [3](#0-2) 

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

Here `stake.delegation.stake` is the *live* delegation value read from the stakes cache at distribution time, while `new_stake.delegation.stake` (`partitioned_stake_reward.inflation.stake`) was computed earlier, at calculation time, from the delegation value as it existed *then*. Partitioned epoch rewards intentionally spread calculation and distribution of stake rewards across many separate blocks/slots within the epoch-rewards period (this is the entire purpose of "partitioned" distribution — to avoid doing all reward payouts in a single slot). Between the calculation snapshot and the actual distribution slot for a given stake account's partition, the stake authority can submit ordinary, permitted instructions — e.g. `Split`, `Merge`, `Withdraw` of excess/rent-exempt lamports, `MoveStake`/`MoveLamports` — that change `stake.delegation.stake` on that account. Such actions are normal user activity, not adversarial exploitation of a bug in the stake program itself; they are exactly analogous to the external report's "asset rebases between payload update and payload processing," where a stored expectation is compared against a live value that legitimately drifted in the interim.

Because the check is `assert_eq!` rather than a returned `Result`/`Err`, any mismatch panics the thread performing `store_stake_accounts_in_partition` (called during bank freezing at each partitioned-rewards distribution slot) instead of being handled as `DistributionError` like every other failure path in this function is designed to be (see the `Err` handling in `store_stake_accounts_in_partition`, which otherwise gracefully burns the reward and logs an error) [4](#0-3) .

### Impact Explanation
A panic inside bank-freezing logic executed identically by every validator (it operates on canonical on-chain stake state, not gossip/network input) will be hit deterministically by all validators at the same distribution slot, since they all compute the same stakes-cache state from the same ledger. This produces a cluster-wide simultaneous panic at an epoch-boundary/reward-distribution slot — an epoch-boundary halt, one of the explicitly in-scope impact categories. Unlike the Superform case (a mere revert of one user's withdrawal transaction), this is a validator process panic, not a graceful instruction failure, which is strictly worse and can stop the whole network from progressing.

### Likelihood Explanation
The precondition is simply that a staker performs one or more ordinary stake operations (split/merge/withdraw excess lamports/move stake) on their account after their epoch rewards have been calculated but before that partition's rewards are distributed — a window that exists by design because Agave partitions reward distribution across multiple blocks specifically to spread out the work. This does not require any special privilege, malicious construction, or precise timing beyond knowing which slot range corresponds to the epoch-rewards distribution period, which is public/derivable information. This condition is gated behind the `relax_post_exec_min_balance_check` feature being inactive; I was unable to fully verify within the available tool budget whether that feature is already active on current mainnet/testnet or still pending activation, which materially affects present-day exploitability of this exact code path.

### Recommendation
Replace the `assert_eq!` with a recoverable error path (returning `DistributionError`, consistent with every other failure branch in `build_updated_stake_reward`/`store_stake_accounts_in_partition`), and/or recompute the expected delegation using the live current stake state at distribution time rather than trusting a delegation value frozen at the earlier calculation phase, analogous to recommending a tolerance/re-derivation instead of a hard equality check in the original report.

### Proof of Concept
1. At the start of the epoch-rewards calculation phase, a staker's stake account has `delegation.stake = S`; the calculation phase computes `stake_reward = R` and caches `new_stake.delegation.stake = S + R` as `partitioned_stake_reward.inflation.stake`.
2. Before that account's partition is reached in the distribution phase (which happens over multiple subsequent blocks), the stake authority submits a legitimate instruction (e.g., `Withdraw` of excess rent-exempt lamports, `Split`, or `MoveStake`) that changes the account's live delegation to `S' != S`.
3. When distribution processes this account's partition, `build_updated_stake_reward` reads the now-live `stake.delegation.stake = S'` and computes `expected_delegation = S' + R`, but `new_stake.delegation.stake` is still the previously cached `S + R`.
4. Since `S' != S`, `expected_delegation != new_stake.delegation.stake`, and the `assert_eq!` at `distribution.rs` panics, crashing the bank-processing thread on every validator processing that slot. [3](#0-2)

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L239-261)
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

        let (mut account, stake_state): (AccountSharedData, StakeStateV2) = stake_account.into();
        let StakeStateV2::Stake(meta, stake, flags) = stake_state else {
            // StakesCache only stores accounts where StakeStateV2::delegation().is_some()
            unreachable!(
                "StakesCache entry {:?} failed StakeStateV2 deserialization",
                partitioned_stake_reward.stake_pubkey
            )
        };
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L610-649)
```rust
    #[expect(clippy::too_many_arguments)]
    fn redeem_delegation_rewards(
        &self,
        rewarded_epoch: Epoch,
        stake_pubkey: &Pubkey,
        stake_account: &StakeAccount<Delegation>,
        point_value: &PointValue,
        stake_history: &StakeHistory,
        cached_vote_accounts: &CachedVoteAccounts<'_>,
        reward_calc_tracer: Option<impl RewardCalcTracer>,
        new_rate_activation_epoch: Option<Epoch>,
        delay_commission_updates: bool,
        commission_rate_in_basis_points: bool,
        adjust_delegations_for_rent: bool,
        ag_epoch_type: &AlpenglowEpochType,
        custom_commission_collector: bool,
        use_fixed_point_stake_math: bool,
    ) -> Option<InflationRewardWithCommission> {
        // curry closure to add the contextual stake_pubkey
        let reward_calc_tracer = reward_calc_tracer.as_ref().map(|outer| {
            // inner
            move |inner_event: &_| {
                outer(&RewardCalculationEvent::Staking(stake_pubkey, inner_event))
            }
        });

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
```
