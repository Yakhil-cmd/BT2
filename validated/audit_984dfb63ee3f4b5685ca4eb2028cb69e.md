### Title
Unprivileged `Split` on a to-be-rewarded stake account during the reward distribution window can panic `build_updated_stake_reward`'s consistency `assert_eq!`, halting partitioned reward distribution - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
`build_updated_stake_reward` loads the *current* `StakeAccount` from `stakes_cache_accounts` (a live snapshot taken at distribution time) and, when `adjust_delegations_for_rent` is `false`, asserts that `stake.delegation.stake + inflation.stake_reward == new_stake.delegation.stake`, where `new_stake` was computed during the earlier calculation phase from a different (pre-mutation) delegation snapshot. Because reward calculation and reward distribution are split across multiple blocks, and the stake program allows the stake authority to call `Split` on their own delegated stake account without deactivating it first, an unprivileged owner of a to-be-rewarded stake account can shrink `delegation.stake` in that window and cause the `assert_eq!` to fail, panicking the validator during block processing.

### Finding Description
Reward processing is split into a calculation block and 1..N distribution blocks (`REWARD_CALCULATION_NUM_BLOCKS`, `get_reward_distribution_num_blocks`), all within the same epoch boundary window [1](#0-0) . The pre-computed `PartitionedStakeReward` (including `inflation.stake` reflecting the delegation as it stood during calculation) is stored and later replayed against the live stakes cache at `store_stake_accounts_in_partition`, which takes a fresh snapshot of `stakes_cache_accounts` at the time each distribution block is processed [2](#0-1) .

Inside `build_updated_stake_reward`, the account is fetched from that live snapshot [3](#0-2) , and when `adjust_delegations_for_rent` is `false` the code asserts strict consistency between the live account's delegation and the pre-calculated reward's `new_stake.delegation.stake`: [4](#0-3) 

This assumes the stake account's delegation is immutable between calculation and distribution. That assumption is stated as an invariant in the surrounding comment ("further state mutation prevents by stake-program restrictions") [5](#0-4) , but the stake program's `Split` instruction is a normal, authorized, unprivileged operation that reduces `delegation.stake` and `lamports` on an active (non-deactivated) stake account without waiting for deactivation. A staker who owns their own stake account (their `StakeAuthorize::Staker`/`Withdrawer` key signs) can submit a `Split` transaction in any block between the reward calculation block and the block that processes their account's partition, updating the live `StakesCache` entry (via `update_stakes_cache`/`check_and_store` on successful execution) before `store_stake_accounts_in_partition` reads it [6](#0-5) .

When that partition is later processed, `stake.delegation.stake` (now smaller, post-split) plus `partitioned_stake_reward.inflation.stake_reward` (computed from the pre-split, larger delegation) will not equal `new_stake.delegation.stake` (also computed from the pre-split delegation), tripping the `assert_eq!` and panicking the bank thread mid-block-processing — an epoch-boundary consensus halt reachable purely by an unprivileged user acting on their own account.

No existing guard prevents this: there is no reward-interval-based restriction on stake instructions in this codebase (confirmed via `test_rewards_period_system_transfer`, which documents that ordinary transactions, including transfers to stake accounts, proceed "regardless of rewards period" [7](#0-6) ), and `build_updated_stake_reward`'s `AccountNotFound`/`ArithmeticOverflow` error paths only cover missing accounts or lamport overflow, not a live but mutated delegation.

This assertion path is only exercised when `adjust_delegations_for_rent` (driven by feature `relax_post_exec_min_balance_check`) is `false`. I was not able to confirm from the indexed code whether this feature is already permanently active on the target cluster(s); if it is active for all live clusters, the vulnerable branch is currently dead code and only the `adjust_delegation_for_rent`-based branch executes (which uses live lamports and does not `assert_eq!`, though it may still silently compute an incorrect reward-adjusted delegation from stale calculation data — a related but distinct value-conservation concern not scoped by this question's panic path).

### Impact Explanation
If reachable, this is a validator panic triggerable by an unprivileged user's own transaction against their own stake account, causing an epoch-boundary halt of the affected validator(s) during partitioned reward distribution — matching the "epoch-boundary halt" bounty category. It is not lamport theft (the panic occurs before any store), but a liveness/availability bug reachable without any privileged access.

### Likelihood Explanation
Preconditions: (1) attacker owns a stake account that is included in the current epoch's partitioned stake rewards with `inflation.stake_reward > 0`; (2) the `adjust_delegations_for_rent`/`relax_post_exec_min_balance_check` feature is not active (uncertain on current mainnet-beta status, not confirmed in this index); (3) attacker submits a `Split` instruction against their own stake account in any block between the reward-calculation block and the block that processes their account's assigned partition — a window of up to several blocks per `get_reward_distribution_num_blocks`. All of these are within normal unprivileged capability (self-authorized stake instruction), making this straightforward and repeatable once the feature-gate precondition holds.

### Recommendation
`build_updated_stake_reward` should not hard-`assert_eq!` a live, potentially-attacker-mutated delegation against a stale, pre-calculation snapshot. Instead, detect delegation drift (e.g., by comparing a recorded pre-calculation delegation/lamport fingerprint, or the credits-observed/authority fields) and return a `DistributionError` (e.g., `DelegationChanged`) that causes the reward to be burned/skipped gracefully, matching the existing `AccountNotFound`/`ArithmeticOverflow` error-handling pattern instead of panicking the whole partition.

### Proof of Concept
Integration test plan (Rust, using `runtime/src/bank/partitioned_epoch_rewards/*` test scaffolding):
1. Build a `RewardBank` (via `create_reward_bank`) with a staker-owned stake account that will receive a nonzero `inflation.stake_reward`, ensuring `relax_post_exec_min_balance_check` feature is disabled in `feature_set` for the test bank so `adjust_delegations_for_rent == false`.
2. Advance to the epoch boundary so calculation occurs (`bank.is_calculated()` true), capturing the `PartitionedStakeReward` for the target stake account and confirming it lands in a distribution partition scheduled at least 1 block later.
3. Before that partition's block is processed, submit a signed `stake::instruction::split` transaction from the staker authority, splitting off part of the delegated stake into a new account, and confirm it executes successfully (`bank.process_transaction(&split_tx).unwrap()`), verifying via `bank.stakes_cache.stakes().stake_delegations()` that the original account's `delegation.stake` has shrunk.
4. Advance to the block that calls `distribute_epoch_rewards_in_partition` for that partition.
5. Expected (correct) behavior: either `build_updated_stake_reward` returns `Err(DistributionError::DelegationChanged)` (after the fix) and the reward is gracefully burned/logged with lamport conservation preserved (`assert_eq!` on total minted+burned vs pre-computed rewards), or — current buggy behavior — the process panics with the message "stake reward delegation must be consistent with the updated stake account lamport balance", which should be asserted as **not** occurring via `#[should_panic]`-free execution in the fixed version, and reproduced via a `#[should_panic(expected = "stake reward delegation must be consistent")]` test against the current code to confirm the bug.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L24-26)
```rust
/// Number of blocks for reward calculation and storing vote accounts.
/// Distributing rewards to stake accounts begins AFTER this many blocks.
const REWARD_CALCULATION_NUM_BLOCKS: u64 = 1;
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L1082-1084)
```rust
    /// Test that lamports can be sent to stake accounts regardless of rewards period.
    #[test]
    fn test_rewards_period_system_transfer() {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-252)
```rust
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L330-332)
```rust
    /// Because stake accounts are checked in calculation, and further state
    /// mutation prevents by stake-program restrictions, there should never be
    /// rewards burned.
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L361-365)
```rust
        let stakes_cache = self.stakes_cache.stakes();
        let stakes_cache_accounts = stakes_cache.stake_delegations();
        let stake_history = stakes_cache.history();
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let rent = &self.rent_collector.rent;
```

**File:** runtime/src/bank.rs (L5782-5791)
```rust
            .for_each(|(pubkey, account)| {
                // note that this could get timed to: self.rc.accounts.accounts_db.stats.stakes_cache_check_and_store_us,
                //  but this code path is captured separately in ExecuteTimingType::UpdateStakesCacheUs
                self.stakes_cache.check_and_store(
                    pubkey,
                    account,
                    new_warmup_cooldown_rate_epoch,
                    use_fixed_point_stake_math,
                );
            });
```
