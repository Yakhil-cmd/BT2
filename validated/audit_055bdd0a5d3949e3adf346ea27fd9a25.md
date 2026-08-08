### Title
Epoch-boundary panic (validator halt) from hardcoded zero block-reward funding in `EpochRewards` sysvar despite nonzero block-reward distribution - ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
`begin_partitioned_rewards` always creates the `EpochRewards` sysvar account with `block_rewards = 0`, regardless of whether block-revenue-sharing rewards will actually be computed and distributed for the epoch. Later, during distribution, `distribute_epoch_rewards_in_partition` sums up all non-zero `block_reward` amounts computed per stake delegation and unconditionally tries to debit that sum from the sysvar account via `update_epoch_rewards_sysvar`, which panics if the account does not hold enough lamports. Because the account was funded with zero extra lamports for block rewards, any epoch in which block-revenue-sharing produces a nonzero total will deterministically panic every validator at the same point in epoch-boundary processing.

### Finding Description
`begin_partitioned_rewards` creates the sysvar with a literal `0` for the `block_rewards` argument: [1](#0-0) 

`create_epoch_rewards_sysvar` uses this argument to fund the account with `rent_exempt_balance + block_rewards` lamports, as demonstrated by the test that explicitly checks `expected_balance = rent_exempt_balance + block_rewards`: [2](#0-1) 

Meanwhile, `calculate_stake_rewards_and_commissions` computes a real, nonzero `block_reward` for every stake delegation whenever the `block_revenue_sharing` feature is active, via `calculate_block_reward`, which distributes a vote account's `pending_delegator_rewards` proportionally by stake: [3](#0-2) [4](#0-3) 

These per-stake `block_reward` values are summed and credited to stake accounts during distribution: [5](#0-4) [6](#0-5) 

and the running total (`block_reward_lamports_distributed + block_reward_lamports_burned`) is passed as `debit_block_reward_lamports` to `update_epoch_rewards_sysvar`: [7](#0-6) 

`update_epoch_rewards_sysvar` then attempts to subtract that amount from the sysvar account's lamports and asserts success: [8](#0-7) 

Since the account was created with `block_rewards = 0` (no lamports reserved for block-reward debits), but the distribution phase computes and tries to debit a nonzero amount, `checked_sub_lamports` fails and the `.expect("epoch reward sysvar has enough lamports for distribution")` panics. This is the same bug class as the Burve report: an amount is calculated and reserved up front (liquidity budget / lamport budget) using a value that does not match what is later actually needed/consumed across the individual allocations (per-range mints / per-stake block rewards), causing a hard failure when the sum is applied against the pre-allocated resource.

### Impact Explanation
Because reward calculation and distribution are part of the deterministic bank state-transition executed identically by all validators, this is not a random node-specific crash: every validator (and any node re-executing/verifying the block) will panic at the exact same point in epoch-boundary processing whenever the `block_revenue_sharing` feature is enabled and any validator earns a nonzero block reward for the epoch (which is the intended common case once the feature and SIMD-0123 revenue sharing are live). This causes a cluster-wide halt at the epoch boundary — matching the "epoch-boundary halt" impact category.

### Likelihood Explanation
Likelihood is high once the `block_revenue_sharing` feature is activated: `calculate_block_reward` unconditionally computes a nonzero reward for any delegation whose vote account has `pending_delegator_rewards > 0`, which is a normal expected state under SIMD-0123 (validators/delegators deposit rewards into `pending_delegator_rewards` via `deposit_delegator_rewards`). No adversarial input or attacker action is required — this triggers under ordinary reward accrual in any epoch with block-revenue-sharing enabled and active delegator deposits.

### Recommendation
Compute the actual total block-reward lamports to be distributed during `calculate_rewards_for_partitioning`/`begin_partitioned_rewards` (sum of per-delegation `block_reward`, e.g., accumulated the same way `total_stake_rewards_lamports` already is), and pass that real total into `create_epoch_rewards_sysvar` instead of the hardcoded `0`, ensuring the sysvar account is funded with enough lamports to cover the block-reward debits performed later in `update_epoch_rewards_sysvar`.

### Proof of Concept
1. Activate the `block_revenue_sharing` feature and SIMD-0123 (`upgrade_bpf_stake_program_to_v5_1`, Alpenglow epoch type).
2. Have a vote account receive a `deposit_delegator_rewards` deposit so `pending_delegator_rewards > 0` (`programs/vote/src/vote_state/mod.rs:936-988`).
3. Advance to the epoch boundary; `begin_partitioned_rewards` creates the `EpochRewards` sysvar with `block_rewards = 0` (`calculation.rs:276-282`).
4. During the distribution phase, `calculate_block_reward` yields a nonzero `block_reward` for the delegation (`calculation.rs:206-231`), which is summed into `block_reward_lamports_distributed` in `store_stake_accounts_in_partition` (`distribution.rs:382-397`).
5. `distribute_epoch_rewards_in_partition` calls `update_epoch_rewards_sysvar(..., block_reward_lamports_distributed + block_reward_lamports_burned)` (`distribution.rs:200-204`), which attempts `account.checked_sub_lamports(debit_block_reward_lamports)` on an account funded with zero extra lamports, triggering the `.expect(...)` panic in `sysvar.rs:98-101`.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L206-231)
```rust
    let total_active_stake = reward_epoch_delegated_stakes
        .delegated_stakes
        .get(&vote_pubkey)
        .copied()
        .unwrap_or(0);
    if total_active_stake == 0 {
        0
    } else {
        let stake = delegation_effective_stake(
            delegation,
            rewarded_epoch,
            stake_history,
            new_warmup_cooldown_rate_epoch,
            use_fixed_point_stake_math,
        );
        // During recalculation, if stake account has already received rewards,
        // it's possible to have `stake > total_active_stake`. If
        // `pending_delegator_rewards` is a huge number, we could potentially
        // overflow a `u64`. We can also have individual rewards look greater
        // than the pending rewards. This is harmless in practice, but we
        // clamp it just to be safe
        (pending_delegator_rewards as u128 * stake as u128 / total_active_stake as u128)
            .try_into()
            .unwrap_or(u64::MAX)
            .min(pending_delegator_rewards)
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L276-282)
```rust
        self.create_epoch_rewards_sysvar(
            distributed_lamports + distributed_to_incinerator_lamports + burned_lamports,
            distribution_starting_block_height,
            num_partitions,
            point_value,
            0, // block_rewards
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L820-833)
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L200-204)
```rust
        // decrease distributed capital from epoch rewards sysvar
        self.update_epoch_rewards_sysvar(
            stake_reward_lamports_minted + stake_reward_lamports_burned,
            block_reward_lamports_distributed + block_reward_lamports_burned,
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L262-267)
```rust
        account
            .checked_add_lamports(partitioned_stake_reward.inflation.stake_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
        account
            .checked_add_lamports(partitioned_stake_reward.block_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L382-397)
```rust
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
                Ok(stake_reward) => {
                    stake_reward_lamports_minted += stake_reward_amount;
                    block_reward_lamports_distributed += block_reward_amount;
                    updated_stake_rewards.push(stake_reward);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L607-612)
```rust
        let pre_epoch_rewards_account = bank.get_account(&sysvar::epoch_rewards::id()).unwrap();
        let expected_balance = bank
            .get_minimum_balance_for_rent_exemption(pre_epoch_rewards_account.data().len())
            + block_rewards;
        // Expected balance is the sysvar rent-exempt balance
        assert_eq!(pre_epoch_rewards_account.lamports(), expected_balance);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/sysvar.rs (L92-105)
```rust
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
```
