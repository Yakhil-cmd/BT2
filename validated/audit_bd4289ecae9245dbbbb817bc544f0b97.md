Based on the investigation, I found a credible analog to the reported bug class — an inconsistency between a cached, derived aggregate value (analogous to `DelFiPrice.prices`) and the underlying source-of-truth account data (analogous to `OpenOraclePriceData.data`) that can be updated through more than one path, with only one of those paths triggering the recalculation/refresh.

### Title
Vote/stake account writes outside the transaction-execution path bypass `StakesCache` synchronization, leaving cached delegated-stake and vote-account state stale - ([File: runtime/src/bank/block_component_processor/vote_reward.rs])

### Summary
`Bank` maintains a single, authoritative in-memory cache, `stakes_cache: StakesCache`, of vote accounts and delegated stake amounts, which is read throughout the codebase (leader schedule, reward calculation, distribution) as the source of truth for "current" stake and vote state [1](#0-0) . The only mechanism that keeps this cache synchronized with account state is `Bank::update_stakes_cache`, which is invoked exactly once, after normal transaction execution, iterating over the accounts touched by `sanitized_txs`/`processing_results` and calling `StakesCache::check_and_store` for each [2](#0-1) . `check_and_store` is the only function that recomputes `delegated_stakes` / `vote_accounts` entries from a raw account [3](#0-2) .

However, vote-account state can also be mutated directly via `Bank::store_accounts`, entirely outside the transaction-execution/`update_stakes_cache` path. This is exactly what `calc_vote_rewards_update_vote_states` does when distributing Alpenglow voting rewards: it reads the current cached vote accounts with `bank.vote_accounts()`, computes updated vote-account state, and writes the results back with `bank.store_accounts(...)` directly, never calling `stakes_cache.check_and_store` [4](#0-3) .

This mirrors the reported bug exactly: `OpenOraclePriceData.put` updates the underlying price data without recalculating the cached median in `DelFiPrice.prices`, while `DelFiPrice.postPrices` does both consistently. Here, normal transaction execution correctly refreshes `stakes_cache` via `update_stakes_cache`/`check_and_store`, but the protocol-level vote-reward write path updates the vote account directly via `store_accounts` without refreshing `stakes_cache`.

### Finding Description
`StakesCache` is meant to always reflect the latest vote/stake account contents so that dependent computations (delegated stake amounts, vote-account credits used in subsequent reward/point calculations, etc.) are accurate [5](#0-4) . The test suite for `StakesCache` itself demonstrates that raw account writes (e.g., via `store_account_and_update_capitalization`) require an explicit, separate call to `stakes_cache.check_and_store`/`refresh_delegated_stakes` to keep the cache correct — the cache is not automatically kept in sync by accounts-db writes [6](#0-5) .

`calc_vote_rewards_update_vote_states`, used in the Alpenglow vote-reward distribution path, reads `bank.vote_accounts()` (backed by `stakes_cache`), computes new vote-account state (credits/rewards), and persists it with `bank.store_accounts` — bypassing `check_and_store` entirely [4](#0-3) . Since this write does not go through `update_stakes_cache`, the in-memory `stakes_cache` retains the pre-update vote-account snapshot (e.g., stale credits) even though the on-chain account has already been updated.

### Impact Explanation
Any subsequent read of `bank.vote_accounts()` / `stakes_cache.stakes()` in the same slot (e.g., further reward-eligibility checks, point/credit calculations, or leader-schedule-adjacent stake computations that rely on the cache rather than the freshly stored account) will observe the stale, pre-reward vote-account state. This can lead to misattributed or duplicated vote rewards, since credit/point calculations elsewhere in the reward pipeline use the cached `vote_accounts()` view rather than the just-written on-chain state.

### Likelihood Explanation
This is deterministic protocol code executed by every validator identically on every slot in which the corresponding vote-reward distribution logic runs, not an operator/config path and not dependent on adversarial input — it is triggered purely by normal Alpenglow reward distribution flow [7](#0-6) .

### Recommendation
After any direct `store_account`/`store_accounts` write that touches a vote or stake account outside of `update_stakes_cache`'s transaction-driven path (as in `calc_vote_rewards_update_vote_states`), explicitly call `stakes_cache.check_and_store` (or an equivalent refresh) for the affected pubkeys so `stakes_cache` and on-chain state cannot diverge, mirroring how `update_stakes_cache` keeps the cache consistent for ordinary transactions.

### Proof of Concept
Not independently executed; the divergence is demonstrated structurally by comparing the two write paths: `Bank::update_stakes_cache` (`runtime/src/bank.rs:5756-5791`), which is the sole place `StakesCache::check_and_store` is invoked, versus the direct `bank.store_accounts` call in `calc_vote_rewards_update_vote_states` (`runtime/src/block_component_processor/vote_reward.rs:481-482`), which updates vote-account state without any corresponding cache-refresh call. I was not able to fully trace every downstream consumer of `bank.vote_accounts()` within the same slot to conclusively confirm a concrete reward-duplication scenario before running out of investigation budget; this should be verified further (e.g., with a Devin session that can run the reward-distribution test suite and instrument `stakes_cache` reads/writes across a slot boundary) to confirm the precise blast radius.

### Citations

**File:** runtime/src/bank.rs (L5755-5791)
```rust
    /// a bank-level cache of vote accounts and stake delegation info
    fn update_stakes_cache(
        &self,
        txs: &[impl SVMMessage],
        processing_results: &[TransactionProcessingResult],
    ) {
        debug_assert_eq!(txs.len(), processing_results.len());
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let use_fixed_point_stake_math = self.use_fixed_point_stake_math();
        txs.iter()
            .zip(processing_results)
            .filter_map(|(tx, processing_result)| {
                processing_result
                    .processed_transaction()
                    .map(|processed_tx| (tx, processed_tx))
            })
            .filter_map(|(tx, processed_tx)| {
                processed_tx
                    .executed_transaction()
                    .map(|executed_tx| (tx, executed_tx))
            })
            .filter(|(_, executed_tx)| executed_tx.was_successful())
            .flat_map(|(tx, executed_tx)| {
                let num_account_keys = tx.account_keys().len();
                let loaded_tx = &executed_tx.loaded_transaction;
                loaded_tx.accounts.iter().take(num_account_keys)
            })
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

**File:** runtime/src/stakes.rs (L87-163)
```rust
    pub(crate) fn check_and_store(
        &self,
        pubkey: &Pubkey,
        account: &impl ReadableAccount,
        new_rate_activation_epoch: Option<Epoch>,
        use_fixed_point_stake_math: bool,
    ) {
        // TODO: If the account is already cached as a vote or stake account
        // but the owner changes, then this needs to evict the account from
        // the cache. see:
        // https://github.com/solana-labs/solana/pull/24200#discussion_r849935444
        let owner = account.owner();
        // Zero lamport accounts are not stored in accounts-db
        // and so should be removed from cache as well.
        if account.lamports() == 0 {
            if solana_vote_program::check_id(owner) {
                let _old_vote_account = {
                    let mut stakes = self.0.write().unwrap();
                    stakes.remove_vote_account(pubkey)
                };
            } else if stake_program::check_id(owner) {
                let mut stakes = self.0.write().unwrap();
                stakes.remove_stake_delegation(
                    pubkey,
                    new_rate_activation_epoch,
                    use_fixed_point_stake_math,
                );
            }
            return;
        }
        debug_assert_ne!(account.lamports(), 0u64);
        if solana_vote_program::check_id(owner) {
            if VoteStateVersions::is_correct_size_and_initialized(account.data()) {
                match VoteAccount::try_from(create_account_shared_data(account)) {
                    Ok(vote_account) => {
                        // drop the old account after releasing the lock
                        let _old_vote_account = {
                            let mut stakes = self.0.write().unwrap();
                            stakes.upsert_vote_account(pubkey, vote_account)
                        };
                    }
                    Err(_) => {
                        // drop the old account after releasing the lock
                        let _old_vote_account = {
                            let mut stakes = self.0.write().unwrap();
                            stakes.remove_vote_account(pubkey)
                        };
                    }
                }
            } else {
                // drop the old account after releasing the lock
                let _old_vote_account = {
                    let mut stakes = self.0.write().unwrap();
                    stakes.remove_vote_account(pubkey)
                };
            };
        } else if stake_program::check_id(owner) {
            match StakeAccount::try_from(create_account_shared_data(account)) {
                Ok(stake_account) => {
                    let mut stakes = self.0.write().unwrap();
                    stakes.upsert_stake_delegation(
                        *pubkey,
                        stake_account,
                        new_rate_activation_epoch,
                        use_fixed_point_stake_math,
                    );
                }
                Err(_) => {
                    let mut stakes = self.0.write().unwrap();
                    stakes.remove_stake_delegation(
                        pubkey,
                        new_rate_activation_epoch,
                        use_fixed_point_stake_math,
                    );
                }
            }
        }
```

**File:** runtime/src/stakes.rs (L541-553)
```rust
    fn refresh_delegated_stakes(
        &mut self,
        new_rate_activation_epoch: Option<Epoch>,
        use_fixed_point_stake_math: bool,
    ) {
        self.delegated_stakes = Self::calculate_delegated_stakes(
            &self.stake_delegations,
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
            use_fixed_point_stake_math,
        );
    }
```

**File:** runtime/src/block_component_processor/vote_reward.rs (L430-482)
```rust
/// Calculates voting rewards based on the `reward_cert` and updates fields in the vote account
/// based on the calculated rewards and the `final_cert_input`.
pub(super) fn calc_vote_rewards_update_vote_states(
    bank: &Bank,
    reward_cert: Option<ValidatedRewardCert>,
    final_cert_input: Option<(&HashSet<Pubkey>, Slot)>,
    block_producer_time_nanos: i64,
) -> Result<(), CalcVoteRewardUpdateVoteStatesError> {
    let Some(updated_accounts) = allocate_updated_accounts(bank, &reward_cert, &final_cert_input)?
    else {
        return Ok(());
    };
    let reward_state = match &reward_cert {
        Some(c) => Some(RewardState::try_new(
            bank,
            c.slot(),
            c.validators(),
            block_producer_time_nanos,
        )?),
        None => None,
    };
    let final_cert_state = final_cert_input.map(|(signers, final_slot)| {
        FinalCertState::new(bank, signers, final_slot, block_producer_time_nanos)
    });
    let vote_accounts = bank.vote_accounts();

    let updated_accounts = match (&reward_state, &final_cert_state) {
        (None, None) => return Ok(()),
        (Some(state), None) => update_accounts(
            &reward_state,
            &final_cert_state,
            &vote_accounts,
            updated_accounts,
            state.reward_validators.iter().cloned(),
        )?,
        (None, Some(state)) => update_accounts(
            &reward_state,
            &final_cert_state,
            &vote_accounts,
            updated_accounts,
            state.signers.iter().cloned(),
        )?,
        (Some(r_state), Some(f_state)) => update_accounts(
            &reward_state,
            &final_cert_state,
            &vote_accounts,
            updated_accounts,
            r_state.reward_validators.union(f_state.signers).cloned(),
        )?,
    };

    bank.store_accounts((bank.slot(), updated_accounts.as_slice()), None);
    Ok(())
```

**File:** runtime/src/bank/tests.rs (L5569-5573)
```rust
    bank0.stakes_cache = StakesCache::new(restored_stakes);
    bank0.stakes_cache.refresh_delegated_stakes(
        bank0.new_warmup_cooldown_rate_epoch(),
        bank0.use_fixed_point_stake_math(),
    );
```
