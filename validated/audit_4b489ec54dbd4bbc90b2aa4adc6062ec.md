## Finding

Given the search results, the closest legitimate analog to the reported bug class (unchecked subtraction on financial/stake accounting state that can be driven negative by external state changes, causing a revert/panic instead of graceful degradation) is the delegated-stake bookkeeping in `Stakes::sub_delegated_stake` in `runtime/src/stakes.rs`.

### Title
Unchecked stake-accounting subtraction panics the validator instead of degrading gracefully - (File: `runtime/src/stakes.rs`)

### Summary
`Stakes::sub_delegated_stake` mirrors the reported bug pattern exactly: it performs a `checked_sub` on the cached `delegated_stakes` total and immediately `.expect()`s success, causing an unrecoverable panic rather than any bounded/clamped correction if the subtrahend ever exceeds the recorded total.

### Finding Description
`sub_delegated_stake` is invoked from `remove_stake_delegation` and `upsert_stake_delegation` [1](#0-0) , both of which run on the hot path every time any unprivileged user's stake account (create/delegate/split/merge/deactivate/withdraw) is stored during block processing [2](#0-1) . The subtraction itself is: [3](#0-2) 
This is structurally identical to the reported `CreditCaller.sol` issue: a running total (`totalMintedAmount` / `delegated_stakes`) is decremented by a per-account value (`usedMintedAmount` / effective stake) that is derived from a *separately recomputed* quantity (`delegation_effective_stake`, which depends on `stake_history` and epoch-relative warmup/cooldown math) rather than being tracked exactly in lockstep. If the effective-stake value computed at removal/replace time (`old_stake`) is ever larger than what was actually added to `delegated_stakes` when the entry was inserted — e.g., due to any inconsistency in warmup/cooldown computation across the two call sites, an out-of-order/duplicate account overwrite, or a stake account's delegation changing state between insert and remove within the same or across epochs — the `checked_sub().expect(...)` panics.

### Impact Explanation
Unlike a reverted user transaction (the DeFi report's failure mode), a panic here occurs inside bank/stakes-cache maintenance code that runs deterministically as part of block replay on every validator. Because it is deterministic over the same block, such a panic would crash all validators processing the block simultaneously — this maps to the accepted "epoch-boundary halt" / "cross-node state divergence" impact class (nodes on different code paths/order of updates may or may not hit it, causing consensus divergence) rather than an isolated crash of one node.

### Likelihood Explanation
Likelihood is low-to-speculative: the `.expect()` is a defensive invariant check, and no concrete instruction sequence was identified in this pass that forces `old_stake`/`removed_stake` to exceed the previously recorded contribution to `delegated_stakes`. The two computations (`add_delegated_stake` at insert time and `sub_delegated_stake` at removal time) both call `delegation_effective_stake` with the same `self.epoch`/`self.stake_history`, so under normal operation they should stay consistent. This is flagged as an analog of the reported bug class per the prompt's instructions, not as a proven, independently exploitable defect.

### Recommendation
Replace the `.expect()`-based panic in `sub_delegated_stake` with a saturating/clamped correction (mirroring the report's recommendation to "minimize losses rather than revert/crash"), and add defensive logging/metrics instead of an unconditional panic, so that any latent inconsistency in effective-stake accounting degrades gracefully instead of taking down block processing.

### Proof of Concept
No concrete transaction sequence was found in this pass that forces the invariant violation; this is reported as a structural analog only, per the scan's bug-class-hint methodology, and should be independently verified before being treated as a live security issue.

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
