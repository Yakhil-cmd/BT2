### Title
Owner-controlled stake mutation (`Split`/`Merge`/`Redelegate`) between reward calculation and partitioned distribution can panic `build_updated_stake_reward`, halting epoch-boundary reward payout - (File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs)

### Summary
`build_updated_stake_reward` recomputes `expected_delegation` from the *current* `StakesCache` entry and asserts it equals the previously-calculated `partitioned_stake_reward.inflation.stake.delegation.stake` via a hard `assert_eq!` rather than returning a recoverable `DistributionError`. If a stake/withdraw authority mutates their own stake account's `delegation.stake` (e.g., via `Split`, `Merge`, or `Redelegate`) between the reward-calculation block and the block that distributes that staker's partition, the assertion fails and panics the validator process that is applying/replaying that block.

### Finding Description
Reward processing happens in two phases separated by potentially many blocks: `calculate_rewards_for_partitioning` snapshots each delegation's post-reward stake into `PartitionedStakeReward.inflation.stake` at the epoch boundary (`runtime/src/bank/partitioned_epoch_rewards/calculation.rs`), and `store_stake_accounts_in_partition` later re-reads the *live* `StakesCache` entry for the same pubkey and reconciles it against that frozen snapshot: [1](#0-0) 

Every other failure mode in this function (`AccountNotFound`, `ArithmeticOverflow`, `UnableToSetState`) is handled by returning `Result::Err(DistributionError)`, which `store_stake_accounts_in_partition` catches and safely burns just that individual staker's reward: [2](#0-1) 

But the delegation-consistency check is instead a hard `assert_eq!`, which will abort/panic the entire validator process instead of degrading gracefully for just that one account. The code comment right above `store_stake_accounts_in_partition` reveals the underlying assumption: *"Because stake accounts are checked in calculation, and further state mutation prevents by stake-program restrictions, there should never be rewards burned."* — i.e. the authors assume some other layer (the stake native program) makes such a same-epoch mutation impossible.

I was unable to locate, in this codebase, the actual enforcement that blocks `Split`/`Merge`/`Redelegate` while `EpochRewards.active == true`. On the contrary, `test_rewards_period_system_transfer` in `runtime/src/bank/partitioned_epoch_rewards/mod.rs` explicitly demonstrates that ordinary transactions targeting a stake account are processed normally during the active reward interval (comment: *"Test that lamports can be sent to stake accounts regardless of rewards period"*), which suggests the bank/runtime layer does not globally block writable non-vote transactions during the reward interval in this version: [3](#0-2) 

If the stake program itself also does not specifically reject `Split`/`Merge`/`Redelegate` while `EpochRewards.active`, an unprivileged staker who owns the stake/withdraw authority could:
1. Wait for the epoch boundary calculation block to snapshot their `PartitionedStakeReward`.
2. Before their partition's distribution block arrives (partitions are spread over multiple subsequent blocks, `distribute_partitioned_epoch_rewards` at `runtime/src/bank/partitioned_epoch_rewards/distribution.rs:78-171`), submit `Split`/`Merge`/`Redelegate` on their own stake account to change `delegation.stake` in `StakesCache`.
3. When `store_stake_accounts_in_partition` is later invoked for their partition, `expected_delegation` (derived from the now-mutated live `StakesCache` entry) will diverge from `new_stake.delegation.stake` (from the frozen snapshot), tripping the `assert_eq!` and panicking.

Because block processing/replay is fully deterministic, every validator applying that same block would panic identically, halting the chain at that slot rather than merely failing one account's reward.

### Impact Explanation
A panic inside bank processing during epoch-boundary reward distribution is a cluster-wide liveness/consensus-halt event: all validators replaying the same block encounter the same `assert_eq!` failure and crash, denying every other staker in that partition (and effectively the whole network) their epoch's one-time reward distribution, and requiring a coordinated fix/patch to resume. This matches the stated invariant category: "epoch-boundary work must be bounded and deterministic; no owner action should be able to abort reward payout for third parties."

### Likelihood Explanation
- Precondition: the attacker only needs to be a normal stake/withdraw authority over their own account (no privileged validator/leader access needed).
- The reward-calculation and distribution phases are intentionally split across multiple blocks (`get_reward_distribution_num_blocks`), giving a real window of one or more slots in which such a mutating instruction could land.
- Feasibility is contingent on whether the stake program actually blocks `Split`/`Merge`/`Redelegate` while `EpochRewards.active` — I could not confirm this guard exists anywhere in the indexed codebase (no `epoch_rewards`/`EpochRewardsActive`-style checks were found in stake-instruction processing paths), which is the load-bearing assumption stated only in a comment, not enforced in code visible here.
- Given the uncertainty in confirming (or refuting) the stake-program-side guard from the available index, this should be treated as a real risk requiring explicit verification, not a confirmed exploit chain end-to-end.

### Recommendation
1. Replace the `assert_eq!` in `build_updated_stake_reward` (`runtime/src/bank/partitioned_epoch_rewards/distribution.rs:284-294`) with a recoverable `DistributionError` variant, consistent with the other three failure branches in the same function, so a mismatched delegation degrades to burning/deferring that one staker's reward rather than panicking the whole node.
2. Explicitly verify and, if missing, add an enforcement point (either in the stake native program's instruction processor, or via a bank-level restriction akin to `RewardInterval::InsideInterval`) that rejects `Split`, `Merge`, and `Redelegate` (and any other instruction that mutates `delegation.stake`) while `EpochRewards.active == true`, so the invariant the code already assumes is actually guaranteed.

### Proof of Concept
```rust
// runtime/src/bank/partitioned_epoch_rewards/distribution.rs (integration-style test)
#[test]
fn test_stake_mutation_between_calculation_and_distribution_panics() {
    // 1. Build a reward bank with >1 partition (create_reward_bank helper already
    //    used by test_recalculate_partitioned_rewards / test_rewards_computation_and_partitioned_distribution_multi_blocks).
    // 2. Advance to the epoch-boundary calculation block; assert bank.is_calculated().
    // 3. Before advancing to the block that will distribute the target stake_pubkey's
    //    partition, submit a `Split` (or `Merge`/`Redelegate`) transaction from the
    //    owning stake/withdraw authority against that same stake_pubkey, changing
    //    its live StakesCache delegation.stake.
    // 4. Advance to the distribution block for that partition and call
    //    Bank::store_stake_accounts_in_partition (or drive it via
    //    distribute_partitioned_epoch_rewards / new_from_parent).
    //
    // Expected (if vulnerable): the process panics inside build_updated_stake_reward's
    // assert_eq!("stake reward delegation must be consistent ...") instead of returning
    // Err(DistributionError) and continuing to distribute other stakers' rewards.
    //
    // Expected (if patched): build_updated_stake_reward returns
    // Err(DistributionError::DelegationMismatch) (or similar), that single stake's
    // reward is burned/logged, and store_stake_accounts_in_partition completes
    // successfully for all other indices in the partition.
}
```

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

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L1082-1165)
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
        let vote_key = validator_keypairs[0].vote_keypair.pubkey();
        let vote_account = genesis_config
            .accounts
            .iter()
            .find(|(address, _)| **address == vote_key)
            .map(|(_, account)| account)
            .unwrap()
            .clone();

        let new_stake_signer = Keypair::new();
        let new_stake_address = new_stake_signer.pubkey();
        let new_stake_account = Account::from(stake_utils::create_stake_account(
            &new_stake_address,
            &vote_key,
            &vote_account.into(),
            &genesis_config.rent,
            2_000_000_000,
        ));
        genesis_config
            .accounts
            .extend(vec![(new_stake_address, new_stake_account)]);

        let (mut previous_bank, bank_forks) = Bank::new_with_bank_forks_for_tests(&genesis_config);
        let num_slots_in_epoch = previous_bank.get_slots_in_epoch(previous_bank.epoch());
        assert_eq!(num_slots_in_epoch, 32);

        let transfer_amount = 5_000;

        for slot in 1..=num_slots_in_epoch + 2 {
            let bank = Bank::new_from_parent_with_bank_forks(
                bank_forks.as_ref(),
                previous_bank.clone(),
                SlotLeader::default(),
                slot,
            );

            // Fill bank_forks with banks with votes landing in the next slot
            // So that rewards will be paid out at the epoch boundary, i.e. slot = 32
            let tower_sync = TowerSync::new_from_slot(slot - 1, previous_bank.hash());
            let vote = vote_transaction::new_tower_sync_transaction(
                tower_sync,
                previous_bank.last_blockhash(),
                &validator_vote_keypairs.node_keypair,
                &validator_vote_keypairs.vote_keypair,
                &validator_vote_keypairs.vote_keypair,
                None,
            );
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

            // Push a dummy blockhash, so that the latest_blockhash() for the transfer transaction in each
            // iteration are different. Otherwise, all those transactions will be the same, and will not be
            // executed by the bank except the first one.
            bank.register_unique_recent_blockhash_for_test();
            previous_bank = bank;
        }
    }
```
