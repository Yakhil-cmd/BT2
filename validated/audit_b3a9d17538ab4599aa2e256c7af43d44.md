### Title
Panic while holding the `StakesCache` write lock poisons it and permanently halts the bank - ([File: runtime/src/stakes.rs])

### Summary
`StakesCache` wraps the entire vote/stake accounting state (`Stakes<StakeAccount>`) in a `std::sync::RwLock` and is mutated on the hot path of every transaction that touches a vote or stake account via `StakesCache::check_and_store` [1](#0-0) . Several of the internal mutation routines invoked while the write lock is held use `.expect(...)` on invariants that assume the delegated-stake bookkeeping is always perfectly consistent with the on-chain stake account state, most notably `Stakes::sub_delegated_stake` [2](#0-1) . If any of these invariants is violated, the thread panics while the `RwLock` write-guard is still held, poisoning the lock. Because every accessor to `StakesCache` (`stakes()`, `check_and_store()`, `activate_epoch()`, `refresh_delegated_stakes()`) does `.read().unwrap()` / `.write().unwrap()` on the same underlying lock [3](#0-2) [4](#0-3) [5](#0-4) , once the lock is poisoned every subsequent transaction that touches a stake or vote account (i.e. every call to `Bank::update_stakes_cache` during `commit_transactions`) will also panic when it tries to `.unwrap()` the poisoned guard. This is a structural analog of the reported bug class: an unprivileged, reachable code path takes a mutable lock on global validator state, can panic while holding it, and the failure mode leaves that lock permanently unusable, rendering the bank instance perpetually unresponsive to any further stake/vote related transaction processing.

### Finding Description
`StakesCache::check_and_store` is called for every account touched by a successfully-executed transaction from `Bank::update_stakes_cache`, itself invoked unconditionally from `Bank::commit_transactions` on the banking/replay hot path [6](#0-5) [7](#0-6) . For an account owned by the stake program that is drained to zero lamports (a normal, unprivileged operation — e.g. `Withdraw`), `check_and_store` acquires the write lock and calls `Stakes::remove_stake_delegation` [8](#0-7) , which in turn calls `sub_delegated_stake` [9](#0-8) :

```rust
fn sub_delegated_stake(&mut self, voter_pubkey: &Pubkey, stake: u64) {
    if stake == 0 { return; }
    let current_stake = self.delegated_stakes
        .get_mut(voter_pubkey)
        .expect("subtraction from missing delegated stake");
    *current_stake = current_stake
        .checked_sub(stake)
        .expect("subtraction value exceeds delegated stake");
    ...
}
```

Both `.expect()` calls assume the `delegated_stakes` accounting is always perfectly synchronized with `effective_stake` computed for the removed delegation. Any divergence — e.g. from a difference in `new_rate_activation_epoch` / `use_fixed_point_stake_math` feature-gate values between the time a delegation was added to the cache and the time it is removed, from stake history entries changing between calls, or from any other computation drift in `delegation_effective_stake` — makes either `.expect()` panic. This panic occurs **while the `RwLock` write guard obtained in `check_and_store` is still on the stack** [10](#0-9) , so unwinding poisons the lock (`std::sync::RwLock` poisoning semantics). Every other place in the codebase that reads or writes `StakesCache` calls `.read().unwrap()`/`.write().unwrap()` and will itself panic on the poisoned lock forever afterward [3](#0-2) [11](#0-10) [12](#0-11) , meaning the bank object can no longer commit any transaction touching a vote/stake account, serialize itself for snapshotting, or compute equality checks used in tests/consensus paths.

This is the direct analog of the reported issue: a globally shared, mutably-locked piece of validator state (`STATE`/global lock in the ICP report ↔ `StakesCache`'s `RwLock<Stakes<...>>` here) can be permanently wedged by an unprivileged-triggerable panic while the write lock is held, and there is no mechanism to detect or recover from the poisoned state.

### Impact Explanation
If reachable, this would cause a permanent halt for the affected bank/validator process: no further stake or vote account updates could be applied, subsequent transactions touching stake/vote accounts would panic the processing thread, and the bank's internal invariant checks (equality, serialization for snapshots) would also panic, effectively taking a validator node offline until restarted. This matches the report's class of "permanently frozen account/state" and cross-node behavior divergence, since some nodes may hit the divergent accounting path and others may not (e.g., depending on feature-activation-epoch race conditions), which could contribute to consensus/state divergence.

### Likelihood Explanation
The reachability of an actual divergence between the delegated-stake bookkeeping and the removed-delegation's effective stake is not concretely demonstrated here — the intended invariant is that `check_and_store` is always called with a monotonically consistent `new_rate_activation_epoch`/`use_fixed_point_stake_math`/`stake_history` view for a given epoch, and normal usage (withdraw fully draining a stake account, deactivate+withdraw) should keep the running totals consistent. I was not able to construct or confirm a concrete unprivileged transaction sequence in the available code that provably desynchronizes `delegated_stakes` from the true effective stake of a live delegation before removal (e.g. a feature-flag toggle mid-epoch, or a stake history edge case). This is a genuine `.expect()`-triggered brittleness on a lock held across a hot, transaction-reachable path, but confirming actual triggerability requires deeper analysis of `delegation_effective_stake` and epoch-boundary state transitions than what is available in the indexed portion of the repository.

### Recommendation
- Replace the `.expect()` calls in `Stakes::sub_delegated_stake` with saturating/checked arithmetic that logs and self-heals (e.g., clamps to zero and logs an error) instead of panicking, so an accounting mismatch cannot poison the lock.
- Avoid holding the `RwLock` write guard across any code that can panic; validate/compute all values needed for the mutation before acquiring the lock, then perform only infallible mutation while holding it.
- Consider using `parking_lot::RwLock` (non-poisoning) or explicitly recovering from `PoisonError` (`.into_inner()`) at each call site so a single panic cannot permanently disable subsequent `StakesCache` access.

### Proof of Concept
Not constructed — a full PoC would require producing a stake-program transaction sequence (e.g., interleaved `DeactivateDelegation`/`Withdraw` calls that straddle an epoch boundary or a `use_fixed_point_stake_math` feature activation) that causes `delegation_effective_stake` to return a different value at `remove_stake_delegation` time than the value used when the stake was originally added to `delegated_stakes`, thereby triggering the `.expect()` panic inside the write-locked `check_and_store` path [9](#0-8) . This requires empirical testing against `runtime/src/stakes.rs`'s epoch-activation and fixed-point-math logic that was not available to inspect further at this analysis depth.

### Citations

**File:** runtime/src/stakes.rs (L83-85)
```rust
    pub(crate) fn stakes(&self) -> RwLockReadGuard<'_, Stakes<StakeAccount>> {
        self.0.read().unwrap()
    }
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

**File:** runtime/src/stakes.rs (L166-184)
```rust
    pub(crate) fn activate_epoch(
        &self,
        next_epoch: Epoch,
        stake_history: StakeHistory,
        vote_accounts: VoteAccounts,
        delegated_stakes: DelegatedStakes,
    ) {
        let mut stakes = self.0.write().unwrap();
        stakes.activate_epoch(next_epoch, stake_history, vote_accounts, delegated_stakes)
    }

    pub(crate) fn refresh_delegated_stakes(
        &self,
        new_rate_activation_epoch: Option<Epoch>,
        use_fixed_point_stake_math: bool,
    ) {
        let mut stakes = self.0.write().unwrap();
        stakes.refresh_delegated_stakes(new_rate_activation_epoch, use_fixed_point_stake_math);
    }
```

**File:** runtime/src/stakes.rs (L562-576)
```rust
    fn sub_delegated_stake(&mut self, voter_pubkey: &Pubkey, stake: u64) {
        if stake == 0 {
            return;
        }
        let current_stake = self
            .delegated_stakes
            .get_mut(voter_pubkey)
            .expect("subtraction from missing delegated stake");
        *current_stake = current_stake
            .checked_sub(stake)
            .expect("subtraction value exceeds delegated stake");
        if *current_stake == 0 {
            self.delegated_stakes.remove(voter_pubkey);
        }
    }
```

**File:** runtime/src/stakes.rs (L582-601)
```rust
    fn remove_stake_delegation(
        &mut self,
        stake_pubkey: &Pubkey,
        new_rate_activation_epoch: Option<Epoch>,
        use_fixed_point_stake_math: bool,
    ) {
        if let Some(stake_account) = self.stake_delegations.remove(stake_pubkey) {
            let removed_delegation = stake_account.delegation();
            let removed_stake = delegation_effective_stake(
                removed_delegation,
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
                use_fixed_point_stake_math,
            );
            self.sub_delegated_stake(&removed_delegation.voter_pubkey, removed_stake);
            self.vote_accounts
                .sub_stake(&removed_delegation.voter_pubkey, removed_stake);
        }
    }
```

**File:** runtime/src/bank.rs (L740-740)
```rust
            && *stakes_cache.stakes() == *other.stakes_cache.stakes()
```

**File:** runtime/src/bank.rs (L2284-2284)
```rust
            stakes: self.stakes_cache.stakes().clone(),
```

**File:** runtime/src/bank.rs (L4389-4392)
```rust
        // Cached vote and stake accounts are synchronized with accounts-db
        // after each transaction.
        let ((), update_stakes_cache_us) =
            measure_us!(self.update_stakes_cache(sanitized_txs, &processing_results));
```

**File:** runtime/src/bank.rs (L5755-5792)
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
    }
```
