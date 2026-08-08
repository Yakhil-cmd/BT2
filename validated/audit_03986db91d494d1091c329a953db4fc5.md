### Title
Attacker-controlled stake mutation between epoch-reward calculation and distribution can trigger `assert_eq!` panic in `build_updated_stake_reward` - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
`build_updated_stake_reward` recomputes `expected_delegation` from the **live** `stakes_cache` entry at distribution time and compares it via `assert_eq!` against `new_stake.delegation.stake`, a value baked into `PartitionedStakeReward` during the earlier calculation phase. If the stake/withdraw authority mutates their own stake account's delegation (e.g. via `Split` or `Withdraw`) in any block between the calculation block and their assigned distribution partition block, the two values diverge and the `assert_eq!` panics, crashing every validator that replays that block.

### Finding Description
During the `adjust_delegations_for_rent = false` path, `build_updated_stake_reward` does: [1](#0-0) [2](#0-1) 

`stake` here is fetched fresh from `stakes_cache_accounts` — the bank's **current** stake delegations at the moment the distribution block is processed — while `new_stake` (and therefore `new_stake.delegation.stake`) comes from `partitioned_stake_reward.inflation.stake`, a value computed once during the earlier reward-calculation phase and cached in `PartitionedStakeReward` for later use at `store_stake_accounts_in_partition`: [3](#0-2) 

The reward distribution can span multiple blocks (`REWARD_CALCULATION_NUM_BLOCKS`, then one block per partition), during which the epoch-reward status is `Active` but ordinary transactions continue to be processed unrestricted — confirmed by `test_rewards_period_system_transfer`, explicitly documented as "Test that lamports can be sent to stake accounts regardless of rewards period": [4](#0-3) 

The code comment above `store_stake_accounts_in_partition` explicitly assumes stake-account mutation is blocked by "stake-program restrictions" during this window: [5](#0-4) 

However, extensive searching of the stake program and transaction-processing pipeline (`RewardInterval`, `EpochRewardStatus`, feature-gate checks) found no code that actually enforces this restriction against `Split`/`Withdraw`/`Merge` instructions signed by the account's own stake/withdraw authority — only an RPC-level `EpochRewardsPeriodActive` error was found, which only prevents *querying* reward info via `getBlock`, not the underlying consensus-level transaction processing.

If a `Split` or `Withdraw` transaction (self-authorized, requiring no privileged access) changes `delegation.stake` on an account already scheduled in `PartitionedStakeReward` before its distribution partition's block height is reached, `expected_delegation` (computed from the new/decreased live stake) will not equal `new_stake.delegation.stake` (computed from the old/pre-mutation stake plus reward), and the `assert_eq!` fires unconditionally in release builds (unlike `debug_assert!`), aborting the validator process.

### Impact Explanation
This is a deterministic, network-wide panic reachable purely through native (non-BPF) `Bank`/stake-program code triggered by an ordinary, self-authorized instruction sequence. Because every validator replays the same block deterministically, this causes a synchronized crash across the cluster at the same slot — a consensus halt / liveness failure, matching Agave's "loss of liveness" / "network not being able to confirm new transactions" bounty category.

### Likelihood Explanation
Preconditions are minimal and fully attacker-controlled: own a stake account with any nonzero delegated stake, be its own stake/withdraw authority, and be scheduled for partitioned reward distribution (essentially any staker, since virtually all active stake accounts receive some reward each epoch). The attacker only needs to land a `Split` or `Withdraw` transaction referencing their own account in any block between the reward-calculation block and their assigned distribution block — a window that spans multiple slots for any epoch large enough to require partitioning (`REWARD_CALCULATION_NUM_BLOCKS` + `num_partitions` blocks). This is repeatable every epoch and requires no coordination with validators, leaders, or other parties.

### Recommendation
`build_updated_stake_reward` should not assert equality against a live, potentially attacker-mutated `stakes_cache` value computed from data captured at a different point in time. Instead:
- Recompute `new_stake` deterministically from the *current* live delegation plus the recorded `stake_reward`, ignoring/discarding the stale calculation-time delegation snapshot entirely (mirroring what the `adjust_delegations_for_rent = true` branch already does safely), or
- Detect the mismatch and return a `DistributionError` (e.g., a new `DelegationChanged` variant) instead of panicking, treating the reward as burned/skipped exactly like the existing `AccountNotFound`/`ArithmeticOverflow` error paths, or
- Actually enforce the documented invariant by blocking stake-account-mutating instructions (`Split`, `Withdraw`, `Merge`, `DeactivateDelinquent`, etc.) for any account with a pending, uncredited `PartitionedStakeReward` during `EpochRewardStatus::Active`.

### Proof of Concept
```rust
// runtime/src/bank/partitioned_epoch_rewards/distribution.rs (new test)
#[test]
fn test_split_between_calculation_and_distribution_panics_assert_eq() {
    // 1. Build a bank with one active, delegated stake account owned/withdrawable
    //    by an attacker keypair (similar to create_reward_bank_with_specific_stakes).
    // 2. Advance to the epoch boundary so `begin_partitioned_rewards` runs and
    //    captures `PartitionedStakeReward { inflation.stake.delegation.stake = S, .. }`
    //    for the attacker's stake account into `EpochRewardPhase::Calculation`.
    // 3. Before the bank reaches `distribution_starting_block_height` for the
    //    partition containing the attacker's account, submit a signed
    //    `StakeInstruction::Split` (or `Withdraw`) transaction from the
    //    attacker's own stake/withdraw authority against that same stake
    //    account, reducing its `delegation.stake` to S' != S.
    // 4. Advance the bank to the block where
    //    `distribute_partitioned_epoch_rewards` -> `store_stake_accounts_in_partition`
    //    -> `Bank::build_updated_stake_reward` processes this account.
    //
    // Expected (buggy) result: the process panics with
    // "stake reward delegation must be consistent with the updated stake
    //  account lamport balance" from the `assert_eq!` in
    // `build_updated_stake_reward`, i.e. the test should be run with
    // `#[should_panic(expected = "stake reward delegation must be consistent")]`
    // to demonstrate the crash.
    //
    // Expected (fixed) result: `build_updated_stake_reward` returns
    // `Err(DistributionError::DelegationChanged)` (or recomputes safely) instead
    // of panicking, and `store_stake_accounts_in_partition` continues without
    // aborting the process.
}
```

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-261)
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L329-335)
```rust
    /// stored, the sum of all rewards burned, and the updated StakeRewards.
    /// Because stake accounts are checked in calculation, and further state
    /// mutation prevents by stake-program restrictions, there should never be
    /// rewards burned.
    ///
    /// Note: even if staker's reward is 0, the stake account still needs to be
    /// stored because credits observed has changed
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L360-393)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L1082-1096)
```rust
    /// Test that lamports can be sent to stake accounts regardless of rewards period.
    #[test]
    fn test_rewards_period_system_transfer() {
        let validator_vote_keypairs = ValidatorVoteKeypairs::new_rand();
        let validator_keypairs = vec![&validator_vote_keypairs];
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_vote_accounts(
            1_000_000_000,
            &validator_keypairs,
            vec![1_000_000_000; 1],
        );

```
