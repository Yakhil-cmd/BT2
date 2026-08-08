### Title
Reward distribution can panic on `assert_eq!` when a stake account's on-chain delegation diverges from the value computed at reward-calculation time - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
`build_updated_stake_reward` finalizes each stake account's reward payout at *distribution* time using a `PartitionedStakeReward` that was computed earlier, during the *calculation* phase. When the `relax_post_exec_min_balance_check` feature is not active, the function re-derives the expected post-reward delegation from the **current** stakes-cache entry and asserts it equals the delegation value that was **precomputed** during calculation:

```
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
``` [1](#0-0) 

If `stake.delegation.stake` (the value in the stakes cache **at distribution time**) differs from the delegation that was current **at calculation time** — for example because a validator was destaked/re-delegated, or the delegation was otherwise mutated between the epoch-boundary calculation block and one of the later distribution blocks — this assertion fails and panics.

### Finding Description
Partitioned epoch rewards are computed once, at the epoch boundary (`calculate_stake_rewards_and_commissions`), producing a `PartitionedStakeRewards` snapshot that is then applied over multiple subsequent blocks (`store_stake_accounts_in_partition` → `build_updated_stake_reward`) [2](#0-1) . This time gap between calculation and distribution is exactly the same bug class described in the external report: reward bookkeeping that assumes a value (there, `currentStore.reward`; here, the pre-computed `new_stake.delegation.stake`) will never diverge from a value re-derived from mutable state (there, `getRewardForStakingStore` with a possibly-decreased `principal`/`rewardRatePerDay`; here, `stake.delegation.stake` read live from `stakes_cache_accounts`), and hard-asserts on that assumption instead of gracefully handling a mismatch.

The code comment above `store_stake_accounts_in_partition` explicitly acknowledges the fragility of this invariant: "Because stake accounts are checked in calculation, and further state mutation prevents by stake-program restrictions, there should never be rewards burned" [3](#0-2) . This is a documented assumption, not an enforced guarantee at this code site — the assertion itself is the only thing standing between silent inconsistency and a hard panic. Unlike the `AccountNotFound`/`ArithmeticOverflow`/`UnableToSetState` paths in the same function, which return a `DistributionError` and are handled gracefully by burning the reward and logging an error [4](#0-3) , this particular consistency check is implemented as a Rust `assert_eq!`, which panics the validator process rather than returning `Err(...)`.

The codebase's own regression test (`test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator`) demonstrates that the team is actively aware that stake/vote state can shift between the calculation snapshot and later distribution partitions (e.g., a VAT burn or a distributed partition mutating StakesCache before recalculation) and had to add special handling to keep the "original denominator" consistent for Alpenglow AG rewards [5](#0-4) . That fix covers the AG reward-amount computation, but the `assert_eq!` in `build_updated_stake_reward` is a separate, still-existing hard invariant on `delegation.stake` in the non-`adjust_delegations_for_rent` code path, and is not exercised by that recalculation-specific regression test.

### Impact Explanation
An `assert_eq!` panic inside `build_updated_stake_reward`, which is invoked from `store_stake_accounts_in_partition` during normal block processing at every reward-distribution block, would cause the validator to abort processing of that block. Because this code executes identically on all validators processing the same slot (it is a deterministic part of consensus-critical bank state transitions), a triggering input would cause a simultaneous, cluster-wide panic across all validators at the same block height — an epoch-boundary halt, which is one of the explicitly accepted impact categories.

### Likelihood Explanation
This is a native, unprivileged code path executed automatically for every stake account receiving partitioned rewards; no special validator/operator privileges are required to be "hit" by it — any staker's account participates. However, actually triggering the divergence between the calculation-time and distribution-time delegation values requires demonstrating a concrete sequence of legitimate state transitions (e.g., stake account merge/split/deactivation timing, or snapshot/restore across partitioned reward phases) that can occur between the calculation block and a later distribution block while `relax_post_exec_min_balance_check` is inactive. I was not able to confirm from the available code whether the stake program fully blocks all delegation-mutating instructions for accounts already snapshotted into `PartitionedStakeReward` during the multi-block distribution window, so likelihood is uncertain without further investigation of stake-program instruction handlers.

### Recommendation
Replace the `assert_eq!` in `build_updated_stake_reward` [1](#0-0)  with a non-panicking check that returns a `DistributionError` (consistent with the other failure paths in this function), so that any real-world inconsistency degrades to burning that individual reward and logging an error rather than halting the entire validator/cluster. Additionally, audit and document precisely which stake-program instructions are guaranteed to be blocked for stake accounts with an outstanding partitioned reward during the active distribution window, and add an explicit invariant/test for that guarantee (analogous to `test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator`) so the "should never be rewards burned" comment is enforced rather than assumed.

### Proof of Concept
I could not construct a concrete transaction sequence from the indexed code alone that reliably desynchronizes `stakes_cache_accounts`'s live `delegation.stake` from the value baked into `PartitionedStakeReward.inflation.stake` between the calculation block and a distribution block, while `relax_post_exec_min_balance_check` is disabled. This would require deeper analysis of the stake-program instruction handlers' interaction with the reward-interval/`EpochRewardStatus` state (potentially a Devin session with full repo/test access) to confirm reachability and produce a triggering test case, since the index does not show a complete guard preventing all such mutations at this code path.

### Citations

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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L330-332)
```rust
    /// Because stake accounts are checked in calculation, and further state
    /// mutation prevents by stake-program restrictions, there should never be
    /// rewards burned.
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L336-393)
```rust
    fn store_stake_accounts_in_partition(
        &self,
        partition_rewards: &StartBlockHeightAndPartitionedRewards,
        partition_index: u64,
    ) -> DistributionResults {
        let feature_snapshot = self.feature_set.snapshot();
        // Name intentionally doesn't match -- "adjust delegations for rent" is
        // part of relaxing post-exec min balance checks.
        let adjust_delegations_for_rent = feature_snapshot.relax_post_exec_min_balance_check;
        let use_fixed_point_stake_math = feature_snapshot.upgrade_bpf_stake_program_to_v5_1;

        let mut stake_reward_lamports_minted = 0;
        let mut stake_reward_lamports_burned = 0;
        let mut block_reward_lamports_distributed = 0;
        let mut block_reward_lamports_burned = 0;
        let indices = partition_rewards
            .partition_indices
            .get(partition_index as usize)
            .unwrap_or_else(|| {
                panic!(
                    "partition index out of bound: {partition_index} >= {}",
                    partition_rewards.partition_indices.len()
                )
            });
        let mut updated_stake_rewards = Vec::with_capacity(indices.len());
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
                use_fixed_point_stake_math,
            ) {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L394-407)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L2793-2797)
```rust
        assert_eq!(
            unpaid_reward.inflation.stake_reward, recalculated_unpaid_reward.inflation.stake_reward,
            "recalculation after partial distribution must use the same AG delegated stake \
             denominator as the original epoch-boundary calculation"
        );
```
