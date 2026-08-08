### Title
Withdraw+re-delegate of a stake account between reward calculation and its scheduled distribution partition causes `build_updated_stake_reward` to panic on a stale-delegation consistency assert, halting block processing - (File: `runtime/src/bank/partitioned_epoch_rewards/distribution.rs`)

### Summary
`store_stake_accounts_in_partition`/`build_updated_stake_reward` looks up the stake account to be credited from the **live** `StakesCache` at the moment its partition is processed, not from a snapshot taken at reward-calculation time. If an attacker withdraws their stake account to zero (removing it from `StakesCache`) and re-delegates a new stake account at the same pubkey with a different stake amount before that pubkey's scheduled partition block, `build_updated_stake_reward` merges the *stale* calculated `Stake` (voter, delegation amount, credits_observed) computed at calculation time onto the *current* (unrelated) account, and hits `assert_eq!(expected_delegation, new_stake.delegation.stake, ...)`, which panics deterministically for every validator processing that block.

### Finding Description
`store_stake_accounts_in_partition` resolves the stake account to update via `self.stakes_cache.stakes()` taken fresh at the time the partition is distributed: [1](#0-0) 

`build_updated_stake_reward` then fetches the account by pubkey from this live cache and blends it with the `PartitionedStakeReward` computed earlier during `calculate_rewards_for_partitioning` (which snapshotted stake rewards well before distribution, delayed by `REWARD_CALCULATION_NUM_BLOCKS` and further by up to 10% of the epoch's slots for later partitions): [2](#0-1) 

The routine then overwrites the account's `Stake` (delegation, credits_observed) entirely with the value computed at calculation time (`partitioned_stake_reward.inflation.stake`), while `meta`/`flags` come from whatever account currently occupies that pubkey: [3](#0-2) 

When the `relax_post_exec_min_balance_check` feature (`adjust_delegations_for_rent`) is not active, the code instead asserts that the *current* account's stake plus the calculated reward equals the *stale* computed delegation amount: [4](#0-3) 

Exploit flow:
1. Attacker has a stake account `S` with delegation/stake amount `X` that earns `stake_reward` at epoch boundary; `calculate_rewards_for_partitioning` snapshots `PartitionedStakeReward{ stake_pubkey: S, inflation.stake: X + reward, ... }` into `all_stake_rewards`, and the partition assignment for `S` is fixed via `hash_rewards_into_partitions` once distribution begins (publicly observable on-chain).
2. Attacker computes which future block height corresponds to `S`'s partition index and, before that block, sends a `Withdraw` draining `S` to zero lamports. `StakesCache::check_and_store` removes `S` from `stake_delegations` on zero-lamport store.
3. Attacker creates a brand-new stake account at the *same pubkey* `S` (e.g. via `CreateAccountWithSeed`/`Allocate`+`Assign` to stake program, then `Initialize`+`DelegateStake`) with a different stake amount `Y ≠ X`.
4. When `S`'s partition block height is reached, `build_updated_stake_reward` finds `S` present again in `stakes_cache_accounts` (this is the *new* account, since the cache is live, not a calculation-time snapshot) and evaluates `expected_delegation = Y + reward`, comparing it against `new_stake.delegation.stake = X + reward` from the stale calculation. Since `Y ≠ X`, the assertion fails and the validator panics inside `distribute_epoch_rewards_in_partition`, which runs synchronously as part of normal block/epoch-boundary processing on every validator.

This is not stopped by any signer/authority/rent/overflow guard because the code implicitly (and incorrectly) assumes the pubkey-to-account binding is immutable between calculation and distribution — an assumption an unprivileged staker can break using only ordinary `Withdraw`/`DelegateStake` instructions on their own account.

### Impact Explanation
Because the panic occurs deterministically inside consensus-critical block processing (`distribute_partitioned_epoch_rewards` → `distribute_epoch_rewards_in_partition` → `store_stake_accounts_in_partition` → `build_updated_stake_reward`), every validator processing that specific block height will hit the identical `assert_eq!` and crash/panic, producing a cluster-wide epoch-boundary halt. This falls squarely in the "epoch-boundary halt" / "cross-node state divergence" bounty category. Even where the `relax_post_exec_min_balance_check` feature is active and the assert is bypassed, the surrounding logic still writes back a `Stake` whose delegation/voter/credits_observed originate from the destroyed old account onto the new account (with only lamports and rent-based clamping reflecting the new account), producing an inconsistent, misattributed stake/reward record.

### Likelihood Explanation
This requires only unprivileged actions on an account the attacker owns and controls (`Withdraw`, `Initialize`/`DelegateStake`), no validator/leader/gossip control. Partition assignment is deterministically derivable from the public `parent_blockhash` once distribution starts, giving the attacker a predictable window of up to several thousand blocks (partitioned reward interval, capped at 10% of slots per epoch) to execute the withdraw/redelegate sequence before their partition's block height. The only precondition is choosing a new stake amount different from the original snapshot value, which is trivial for the attacker to guarantee.

### Recommendation
`build_updated_stake_reward`/`store_stake_accounts_in_partition` must not trust the live `StakesCache` entry to still correspond to the account that earned the reward. At minimum, re-validate that the fetched account's identity/state is consistent with the state used during calculation (e.g., by tracking and comparing a fingerprint such as the calculation-time lamports/stake, or by snapshotting/pinning the exact account bytes used at calculation time and using that snapshot, applying only the reward delta atomically instead of overwriting `Stake` wholesale). If the live account no longer matches the expected pre-reward state (whether re-delegated, resized, or reassigned), the reward should be treated as `AccountNotFound`/burned rather than blended, and the `assert_eq!` should be converted into a recoverable error path rather than a process-aborting panic.

### Proof of Concept
Integration test plan (bank test harness, similar to existing `test_recalculate_partitioned_rewards` tests):
1. Build a reward bank with `create_reward_bank_with_specific_stakes` using at least 2 partitions so that the target stake account is *not* in partition 0.
2. Run `calculate_rewards_for_partitioning` at the epoch boundary; capture `all_stake_rewards`/`partition_indices` and identify the stake pubkey `S` with a non-zero `inflation.stake_reward`, note its stake amount `X`.
3. Advance the bank to the first distribution block (so `partition_indices` become fixed and public).
4. Simulate on the still-uncommitted partition for `S`: submit a `Withdraw` on `S` draining to zero lamports (removing it from `StakesCache`), then re-create a stake account at pubkey `S` with a different stake amount `Y` and `DelegateStake`.
5. Advance the bank to the block height corresponding to `S`'s partition index, invoking `distribute_partitioned_epoch_rewards`.
6. Expected (bug) result: the call panics inside `Bank::build_updated_stake_reward` at the `assert_eq!(expected_delegation, new_stake.delegation.stake, ...)` line (when `relax_post_exec_min_balance_check` is inactive), demonstrating the reachable panic; alternatively, assert that `stake_reward_lamports_minted + stake_reward_lamports_burned` no longer equals the original `total_stake_rewards_lamports`, and that the resulting stored `S` account's `Stake.delegation` fields do not correspond to either the pre-withdraw or post-redelegate state, proving state corruption in the feature-active branch.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-268)
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L269-297)
```rust
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
        account
            .set_state(&StakeStateV2::Stake(meta, new_stake, flags))
            .map_err(|_| DistributionError::UnableToSetState)?;
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L361-364)
```rust
        let stakes_cache = self.stakes_cache.stakes();
        let stakes_cache_accounts = stakes_cache.stake_delegations();
        let stake_history = stakes_cache.history();
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
```
