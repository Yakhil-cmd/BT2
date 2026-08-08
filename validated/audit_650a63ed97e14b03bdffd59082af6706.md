## Analog Found

### Title
Stale cached delegated-stake totals cause a hard panic on subtraction underflow, mirroring the Vault `blacklistProtocol` bug - (File: `runtime/src/stakes.rs`, `vote/src/vote_account.rs`)

### Summary
The Sherlock report describes a pattern where a cached aggregate value (`savedTotalUnderlying`) is decremented by a freshly recomputed value that can exceed the cache, causing an unconditional revert. Agave's stake-delegation accounting contains the identical pattern: a cached total (`Stakes::delegated_stakes`, and the per-vote-account `stake`/`staked_nodes` totals in `VoteAccounts`) is decremented using `checked_sub(...).expect(...)`, which panics instead of gracefully clamping, whenever the freshly recomputed "effective stake" being removed exceeds what is cached.

### Finding Description
`Stakes::sub_delegated_stake` unconditionally panics if the value being removed is larger than the cached entry: [1](#0-0) 

The same unconditional-panic pattern exists in the per-vote-account bookkeeping: [2](#0-1) 

Both of these cached totals are maintained incrementally on every stake-account update via `Stakes::upsert_stake_delegation`, which computes the *old* effective stake to subtract by re-running `delegation_effective_stake` on the previously stored `StakeAccount` at the *current* call's parameters, and the *new* effective stake to add using the same parameters: [3](#0-2) 

Critically, `delegation_effective_stake` is not deterministic across the lifetime of the cached value: it switches its underlying math formula (`stake_v2` vs. legacy `stake`) based on the boolean `use_fixed_point_stake_math`, which is derived from a feature-gate snapshot and is passed in fresh on every call site (`store_accounts`, `update_stakes_cache`): [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

Exactly as in the Vault case — where `savedTotalUnderlying` was computed at one point in time (end of `rebalance`) and later compared against a freshly recomputed `balanceUnderlying` that could have drifted upward — here the delegated-stake cache is built incrementally using whatever `use_fixed_point_stake_math` value was in effect at insertion time, while any later update/removal recomputes the "old" contribution using the `use_fixed_point_stake_math` value in effect *at that later call*. If the fixed-point and legacy math formulas ever disagree by even one lamport of effective stake for the same delegation/epoch/history inputs (rounding behavior differs by design, since this is a fixed-point vs. floating-point stake-warmup/cooldown calculation), the "old_stake" subtracted from the cache will not match what was originally added, and `sub_delegated_stake` / `VoteAccounts::sub_stake` / `sub_node_stake` will panic via `.expect(...)`.

### Impact Explanation
A panic inside `Stakes::upsert_stake_delegation` / `remove_stake_delegation` — reachable from ordinary transaction processing every time a staker submits a stake-modifying instruction (delegate, split, merge, withdraw, deactivate) that changes a `StakeAccount`'s lamports/delegation — is not a per-node crash isolated to one validator; because bank state and feature-set activation are consensus-critical and deterministic, this would be hit identically by every validator processing the same transaction/slot, causing a cluster-wide halt at the point the divergence occurs (an epoch-boundary/consensus-halt class event, matching the accepted impact categories).

### Likelihood Explanation
This requires the fixed-point (`stake_v2`) and legacy (`stake`) effective-stake formulas to produce different values for the same delegation/epoch/stake-history inputs at the two different times the cache is touched (insertion vs. later removal/update) — i.e., an unprivileged staker's transaction is processed while the feature-gated math path used by `use_fixed_point_stake_math` differs from the one in effect when the delegation was originally added to the cache. I was not able to fully verify, given tool/iteration limits, whether `Stakes::calculate_activated_stake`/`activate_epoch` (invoked at every epoch boundary) fully and atomically rebuilds `delegated_stakes` with a single consistent flag before any transaction in the new epoch can trigger `upsert_stake_delegation`/`remove_stake_delegation`, which would close this window. This is the key unresolved question that determines whether the divergence is actually reachable in practice.

### Recommendation
- In `Stakes::sub_delegated_stake` (`runtime/src/stakes.rs:562-576`) and `VoteAccounts::sub_stake`/`sub_node_stake` (`vote/src/vote_account.rs:359-421`), replace the panicking `checked_sub(...).expect(...)` with a saturating subtraction (clamping to 0) analogous to the Sherlock report's recommended fix for `savedTotalUnderlying`, so a stale/divergent cached value cannot halt transaction processing.
- Separately, audit `Stakes::upsert_stake_delegation`/`remove_stake_delegation` to guarantee that the `use_fixed_point_stake_math` value used to compute the "old" contribution being removed from the cache is always identical to the value used when that contribution was originally added (e.g., store the flag alongside the cached entry rather than re-deriving it from the live feature-set snapshot on every call).

### Proof of Concept
Not independently reproduced; this analog is derived from static code-path analysis of `runtime/src/stakes.rs` and `vote/src/vote_account.rs` under the time/tool constraints of this session, and the epoch-boundary recompute path (`Stakes::calculate_activated_stake`) that may or may not prevent the divergence was not fully inspected. A concrete PoC would need to construct a bank where `upgrade_bpf_stake_program_to_v5_1` activation timing and a staker's stake-modifying transaction interleave such that the cached `delegated_stakes`/`VoteAccounts` totals were built under one math mode and are decremented under the other.

### Citations

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

**File:** runtime/src/stakes.rs (L620-660)
```rust
    fn upsert_stake_delegation(
        &mut self,
        stake_pubkey: Pubkey,
        stake_account: StakeAccount,
        new_rate_activation_epoch: Option<Epoch>,
        use_fixed_point_stake_math: bool,
    ) {
        debug_assert_ne!(stake_account.lamports(), 0u64);
        let delegation = stake_account.delegation();
        let voter_pubkey = delegation.voter_pubkey;
        let stake = delegation_effective_stake(
            delegation,
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
            use_fixed_point_stake_math,
        );
        match self.stake_delegations.insert(stake_pubkey, stake_account) {
            None => {
                self.add_delegated_stake(voter_pubkey, stake);
                self.vote_accounts.add_stake(&voter_pubkey, stake);
            }
            Some(old_stake_account) => {
                let old_delegation = old_stake_account.delegation();
                let old_voter_pubkey = old_delegation.voter_pubkey;
                let old_stake = delegation_effective_stake(
                    old_delegation,
                    self.epoch,
                    &self.stake_history,
                    new_rate_activation_epoch,
                    use_fixed_point_stake_math,
                );
                if voter_pubkey != old_voter_pubkey || stake != old_stake {
                    self.sub_delegated_stake(&old_voter_pubkey, old_stake);
                    self.add_delegated_stake(voter_pubkey, stake);
                    self.vote_accounts.sub_stake(&old_voter_pubkey, old_stake);
                    self.vote_accounts.add_stake(&voter_pubkey, stake);
                }
            }
        }
    }
```

**File:** vote/src/vote_account.rs (L359-421)
```rust
    pub fn sub_stake(&mut self, pubkey: &Pubkey, delta: u64) {
        let vote_accounts = Arc::make_mut(&mut self.vote_accounts);
        if let Some((stake, vote_account)) = vote_accounts.get_mut(pubkey) {
            *stake = stake
                .checked_sub(delta)
                .expect("subtraction value exceeds account's stake");
            let vote_account = vote_account.clone();
            self.sub_node_stake(delta, &vote_account);
        }
    }

    fn add_node_stake(&mut self, stake: u64, vote_account: &VoteAccount) {
        let Some(staked_nodes) = self.staked_nodes.get_mut() else {
            return;
        };

        VoteAccounts::do_add_node_stake(staked_nodes, stake, *vote_account.node_pubkey());
    }

    fn do_add_node_stake(
        staked_nodes: &mut Arc<HashMap<Pubkey, u64>>,
        stake: u64,
        node_pubkey: Pubkey,
    ) {
        if stake == 0u64 {
            return;
        }

        Arc::make_mut(staked_nodes)
            .entry(node_pubkey)
            .and_modify(|s| *s += stake)
            .or_insert(stake);
    }

    fn sub_node_stake(&mut self, stake: u64, vote_account: &VoteAccount) {
        let Some(staked_nodes) = self.staked_nodes.get_mut() else {
            return;
        };

        VoteAccounts::do_sub_node_stake(staked_nodes, stake, vote_account.node_pubkey());
    }

    fn do_sub_node_stake(
        staked_nodes: &mut Arc<HashMap<Pubkey, u64>>,
        stake: u64,
        node_pubkey: &Pubkey,
    ) {
        if stake == 0u64 {
            return;
        }

        let staked_nodes = Arc::make_mut(staked_nodes);
        let current_stake = staked_nodes
            .get_mut(node_pubkey)
            .expect("this should not happen");
        match (*current_stake).cmp(&stake) {
            Ordering::Less => panic!("subtraction value exceeds node's stake"),
            Ordering::Equal => {
                staked_nodes.remove(node_pubkey);
            }
            Ordering::Greater => *current_stake -= stake,
        }
    }
```

**File:** runtime/src/stake_delegation.rs (L9-23)
```rust
#[inline]
pub(crate) fn delegation_effective_stake<T: StakeHistoryGetEntry>(
    delegation: &Delegation,
    epoch: Epoch,
    history: &T,
    new_rate_activation_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
) -> u64 {
    if use_fixed_point_stake_math {
        delegation.stake_v2(epoch, history, new_rate_activation_epoch)
    } else {
        #[allow(deprecated)]
        delegation.stake(epoch, history, new_rate_activation_epoch)
    }
}
```

**File:** runtime/src/bank.rs (L1717-1721)
```rust
    fn use_fixed_point_stake_math(&self) -> bool {
        self.feature_set
            .snapshot()
            .upgrade_bpf_stake_program_to_v5_1
    }
```

**File:** runtime/src/bank.rs (L4757-4777)
```rust
    pub fn store_accounts<'a>(
        &self,
        accounts: impl StorableAccounts<'a>,
        thread_pool_for_loading_accounts: Option<&ThreadPool>,
    ) {
        assert!(!self.freeze_started());
        let mut m = Measure::start("stakes_cache.check_and_store");
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let use_fixed_point_stake_math = self.use_fixed_point_stake_math();

        (0..accounts.len()).for_each(|i| {
            accounts.account(i, |account| {
                self.stakes_cache.check_and_store(
                    account.pubkey(),
                    &account,
                    new_warmup_cooldown_rate_epoch,
                    use_fixed_point_stake_math,
                )
            })
        });
        self.store_accounts_without_stakes_cache(accounts, thread_pool_for_loading_accounts);
```

**File:** runtime/src/bank.rs (L5756-5791)
```rust
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
