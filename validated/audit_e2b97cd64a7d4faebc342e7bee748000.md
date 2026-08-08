### Title
Unprivileged system-transfer to a stake account can panic `build_updated_stake_reward` during partitioned epoch reward distribution - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
`build_updated_stake_reward` re-derives the post-reward stake delegation using the fresh account state loaded from `stakes_cache_accounts` at distribution time and, when `adjust_delegations_for_rent` is disabled, asserts that this freshly-loaded delegation equals a value computed earlier at calculation time. An unprivileged user can inflate a stake account's raw lamport balance via an ordinary system-program transfer at any point during the reward interval — a path the code base explicitly tests and treats as always allowed regardless of reward status.

### Finding Description
`build_updated_stake_reward` loads the stake account fresh from the stakes cache at distribution time (not the value snapshotted at reward-calculation time), then: [1](#0-0) 
adds the previously-calculated inflation/block reward to the account's lamports, and either adjusts the delegation for rent headroom (`adjust_delegations_for_rent == true`) or falls back to a strict consistency check: [2](#0-1) 
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
`new_stake.delegation.stake` was computed earlier, at reward-calculation time (potentially many blocks before, as `distribute_partitioned_epoch_rewards` can span up to 10% of an epoch's slots) based on the stake account's state at that time: [3](#0-2) 

Meanwhile `stake` in the assert is loaded from the *current* stakes cache at distribution time. The code assumes these two independently-derived values will always match, i.e., that nothing external mutates the stake account's delegation field between calculation and distribution. The comment on the caller states this assumption explicitly ("further state mutation prevents by stake-program restrictions, there should never be rewards burned"): [4](#0-3) 

However, the codebase's own regression test demonstrates that ordinary lamport transfers into a stake account via the System Program succeed at every slot of the reward interval, unconditionally: [5](#0-4) [6](#0-5) 

This mirrors the external report's root cause precisely: code assumes an account balance/derived-state value observed at one point in time still holds unchanged when a later operation is finalized, but non-restricted external actors (an ordinary System Program transfer, analogous to a "fee-on-transfer"/rebasing ERC-20 transfer altering actual balances) can invalidate that assumption in between.

### Impact Explanation
If `adjust_delegations_for_rent` (feature `relax_post_exec_min_balance_check`) is not active and a legitimate concurrent mutation of the delegation amount for a stake account scheduled for rewards occurs between the calculation slot and its assigned distribution partition slot (e.g., via `Redelegate`/`Merge`/`Split`/`Deactivate`-then-new-delegate flows that alter `delegation.stake` for an account that is also queued in `PartitionedStakeReward`), the `assert_eq!` will fail. Because reward distribution is a mandatory, deterministic step of `Bank::new_from_parent` executed identically by every validator, the panic occurs on all nodes processing that slot simultaneously — a deterministic, cluster-wide halt at the epoch boundary rather than a localized failure. This matches the permitted "epoch-boundary halt" impact class.

### Likelihood Explanation
Likelihood is uncertain and cannot be fully confirmed from indexed code alone. The comment in `store_stake_accounts_in_partition` claims "stake-program restrictions" already prevent state mutation of queued stake accounts during the reward interval, but I could not locate (within the indexed portions of the repo) the actual enforcement point that blocks `Redelegate`/`Merge`/`Split` instructions specifically for accounts already captured in a pending `PartitionedStakeReward`, only confirmation that plain System Program transfers (which don't touch `delegation.stake`) are explicitly allowed. Whether a delegation-stake-mutating instruction can reach a stake account in this window (particularly for accounts recalculated via `recalculate_partitioned_rewards_if_active` after a fork/snapshot-restore, which reads stakes fresh) requires further verification of the stake-program instruction processor's reward-interval guard rails, which are not fully covered in this index.

### Recommendation
- Verify and, if necessary, harden the stake-program instruction processor to unconditionally reject any instruction that could change `delegation.stake` for an account with a pending, uncredited `PartitionedStakeReward` entry, for the entire reward interval (calculation through final distribution partition), not just the single calculation slot.
- Replace the hard `assert_eq!` fallback in `build_updated_stake_reward` (used when `adjust_delegations_for_rent` is false) with a recoverable error path (mirroring the `Err(DistributionError::...)` handling already present for other failure cases), so an unexpected mismatch burns/logs the reward instead of panicking the bank.
- Add a regression test that attempts a `Redelegate`/`Merge` on a stake account already captured by `PartitionedStakeReward` during the distribution window and asserts the transaction is rejected (or reward distribution degrades gracefully) rather than panicking.

### Proof of Concept
Cannot be fully constructed from the indexed code alone. A minimal repro would require: (1) confirming which stake instructions are actually permitted against a stake account with `delegation.stake` mutated while it has a queued reward, since only System-Program lamport transfers were confirmed as reachable in `test_rewards_period_system_transfer`; and (2) driving a bank through `begin_partitioned_rewards` → intervening slot with such a mutating instruction → `distribute_partitioned_epoch_rewards` on the affected partition and observing the `assert_eq!` panic in `build_updated_stake_reward`. This construction step could not be completed with the available index; a Devin session with full repository/test access would be needed to locate the exact stake-program instruction-processor code path (not found in this index) that is supposed to enforce the "no state mutation during reward interval" guarantee, and to confirm whether any gap exists.

### Citations

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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L269-294)
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L327-336)
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
    fn store_stake_accounts_in_partition(
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L408-428)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L1082-1097)
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

        // Add stake account to try to mutate
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L1145-1157)
```rust
            bank.process_transaction(&vote).unwrap();

            // Insert a transfer transaction from the mint to new stake account
            let system_tx = system_transaction::transfer(
                &mint_keypair,
                &new_stake_address,
                transfer_amount,
                bank.last_blockhash(),
            );
            let system_result = bank.process_transaction(&system_tx);

            // Credits should always succeed
            assert!(system_result.is_ok());
```
