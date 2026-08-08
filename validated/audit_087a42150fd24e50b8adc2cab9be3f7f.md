`No vulnerability found for this question.`

**Reasoning:** The scenario's precondition—"two different forks with the same `parent_hash` but different stake/vote state"—is self-contradictory in Agave's design. The `parent_hash` used as the cache key in `Bank::calculate_rewards` is the bank hash of the parent bank [1](#0-0) , and a bank's hash is itself a cryptographic commitment to that bank's complete post-transaction account state, including any `DelegateStake`/`Deactivate` effects on stake accounts. Two forks can only share an identical `parent_hash` if they are literally built on the same parent bank (i.e., true siblings created from one common ancestor), which is exactly the case exercised by `test_epoch_rewards_cache_multiple_forks` [2](#0-1) : `bank_fork1` and `bank_fork2` are both children of the same `bank`, so they legitimately reuse the same cached `PartitionedRewardsCalculation`, and that is correct because they share the identical stake-delegation state used as computation input.

If a `DelegateStake`/`Deactivate` transaction landed in fork A's ancestor chain but not fork B's, that transaction's effects would already have altered fork A's ancestor bank's account state and therefore its bank hash, meaning fork A's `parent_hash` would differ from fork B's `parent_hash` (absent a SHA-256/Blake3-class hash collision, which is out of scope as a cryptographic-assumption break, not an exploitable logic bug). The code comment in `calculate_rewards` explicitly documents this design intent — the lock/cache exists to avoid recomputing rewards for the same parent bank state across sequentially-created sibling forks, not across forks with divergent state [3](#0-2) . The `stake_delegations`, `stake_history`, and `cached_vote_accounts` inputs passed into `calculate_rewards` are themselves derived from the shared parent bank's `stakes_cache` in `compute_new_epoch_caches_and_rewards` [4](#0-3) , so identical `parent_hash` guarantees identical inputs by construction, not by coincidence.

Since the attack's stated call sequence ("both forks share parent_hash but differ in stake_delegations input") cannot arise from any reachable attacker-controlled transaction ordering without breaking the underlying hash function's collision resistance, there is no exploitable cross-contamination path here.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L310-328)
```rust
        // We hold the lock here for the epoch rewards calculation cache to prevent
        // rewards computation across multiple forks simultaneously. This aligns with
        // how banks are currently created- all banks are created sequentially.
        // As such, this lock does not actually introduce contention because bank
        // creation (and therefore reward calculation) is always done sequentially.
        //
        // However, if we plan to support creating banks in parallel in the future, this logic
        // would need to change to allow rewards computation on multiple forks concurrently.
        // That said, there's still a compelling reason to keep this lock even in a parallel
        // bank creation model: we want to avoid calculating rewards multiple times for the same
        // parent bank hash. This lock ensures that.
        //
        // Creating bank for multiple forks in parallel would also introduce contention for compute resources,
        // potentially slowing down the performance of both forks. This, in turn, could delay
        // vote propagation and consensus for the leading fork—the one most likely to become rooted.
        //
        // Therefore, it seems beneficial to continue processing forks sequentially at epoch
        // boundaries: acquire the lock for the first fork, compute rewards, and let other forks
        // wait until the computation is complete.
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L329-333)
```rust
        let mut epoch_rewards_calculation_cache =
            self.epoch_rewards_calculation_cache.lock().unwrap();
        let rewards_calculation = epoch_rewards_calculation_cache
            .entry(self.parent_hash)
            .or_insert_with(|| {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L3369-3457)
```rust
    #[test]
    fn test_epoch_rewards_cache_multiple_forks() {
        let (mut genesis_config, _mint_keypair) =
            create_genesis_config(1_000_000 * LAMPORTS_PER_SOL);

        const NUM_STAKES: usize = 1000;

        for _i in 0..NUM_STAKES {
            let vote_pubkey = Pubkey::new_unique();
            let stake_pubkey = Pubkey::new_unique();

            genesis_config.accounts.insert(
                vote_pubkey,
                vote_state::create_v4_account_with_authorized(
                    &vote_pubkey,
                    &vote_pubkey,
                    [0u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
                    &vote_pubkey,
                    0,
                    &vote_pubkey,
                    0,
                    &vote_pubkey,
                    100_000_000_000,
                )
                .into(),
            );

            let stake_lamports = 1_000_000_000_000;
            let stake_account = stake_utils::create_stake_account(
                &stake_pubkey,
                &vote_pubkey,
                &vote_state::create_v4_account_with_authorized(
                    &vote_pubkey,
                    &vote_pubkey,
                    [0u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE],
                    &vote_pubkey,
                    0,
                    &vote_pubkey,
                    0,
                    &vote_pubkey,
                    100_000_000_000,
                ),
                &genesis_config.rent,
                stake_lamports,
            );
            genesis_config
                .accounts
                .insert(stake_pubkey, stake_account.into());
        }

        let (bank, bank_forks) =
            Bank::new_for_tests(&genesis_config).wrap_with_bank_forks_for_tests();
        let next_epoch_slot = bank.get_slots_in_epoch(bank.epoch());
        {
            let cache = bank.epoch_rewards_calculation_cache.lock().unwrap();
            assert!(
                !cache.contains_key(&bank.parent_hash()),
                "cache should be empty"
            );
        }

        let bank_fork1 = Bank::new_from_parent_with_bank_forks(
            bank_forks.as_ref(),
            bank.clone(),
            SlotLeader::default(),
            next_epoch_slot,
        );
        {
            let cache = bank_fork1.epoch_rewards_calculation_cache.lock().unwrap();
            assert!(
                cache.contains_key(&bank_fork1.parent_hash()),
                "cache should be populated"
            );
        }

        // Use new_from_parent (not _with_bank_forks) - we can't insert two banks at same slot
        let bank_fork2 = Arc::new(Bank::new_from_parent(
            bank.clone(),
            SlotLeader::default(),
            next_epoch_slot,
        ));
        {
            let cache = bank_fork2.epoch_rewards_calculation_cache.lock().unwrap();
            assert!(
                cache.contains_key(&bank_fork2.parent_hash()),
                "cache should be populated"
            );
        }
    }
```

**File:** runtime/src/bank.rs (L1762-1803)
```rust
        let stakes = self.stakes_cache.stakes();
        let stake_delegations = stakes.stake_delegations_vec();
        let (
            (
                stake_history,
                unfiltered_distribution_vote_accounts,
                delegated_stakes,
                reward_epoch_delegated_stakes,
            ),
            calculate_activated_stake_time_us,
        ) = measure_us!(stakes.calculate_activated_stake(
            self.epoch(),
            thread_pool,
            self.new_warmup_cooldown_rate_epoch(),
            &stake_delegations,
            self.use_fixed_point_stake_math(),
        ));
        debug_assert_eq!(reward_epoch_delegated_stakes.epoch, rewarded_epoch);

        // Apply stake rewards and commission using the VAT-filtered distribution
        // vote-account snapshot.
        let filtered_distribution_vote_accounts = unfiltered_distribution_vote_accounts
            .clone_and_filter_for_vat(
                MAX_ALPENGLOW_VOTE_ACCOUNTS,
                self.minimum_vote_account_balance_for_vat(),
            );
        if AlpenglowEpochType::is_alpenglow_or_migration_epoch(self, rewarded_epoch) {
            reward_epoch_delegated_stakes.set(self, &filtered_distribution_vote_accounts);
        }
        let cached_vote_accounts =
            self.get_cached_vote_accounts(rewarded_epoch, &filtered_distribution_vote_accounts);
        let (rewards_calculation, update_rewards_with_thread_pool_time_us) =
            measure_us!(self.calculate_rewards(
                &stake_history,
                stake_delegations,
                cached_vote_accounts,
                rewarded_epoch,
                reward_epoch_delegated_stakes,
                reward_calc_tracer,
                thread_pool,
                rewards_metrics,
            ));
```
