### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Skip Block Rewards - (File: `src/staking/staking.cairo`)

---

### Summary
The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no caller access control check. Because `last_reward_block` is a single global variable, any unprivileged address can call `update_rewards` with `disable_rewards: true` to consume the per-block reward slot without distributing any rewards, permanently denying that block's yield to all stakers and their delegators.

---

### Finding Description

The spec at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1449–1507 is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks: is_paused
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence checks ...
    self.last_reward_block.write(current_block_number);   // global slot consumed here
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits with no rewards paid
    }
    // ... actual reward distribution ...
}
```

There is no `get_caller_address()` check anywhere in this function, and a search for any sequencer-related assertion in `staking.cairo` returns zero matches. `general_prerequisites()` only checks the pause flag.

The storage variable `last_reward_block` is a **single global** `BlockNumber` (declared at line 187), not per-staker. The guard `current_block_number > self.last_reward_block.read()` means only **one** call to `update_rewards` can succeed per block across the entire contract.

An attacker can therefore:
1. Call `update_rewards(any_valid_active_staker, disable_rewards: true)` at the start of any block.
2. The call passes all checks (contract not paused, block number is fresh, staker exists and has non-zero balance).
3. `last_reward_block` is written to the current block number (line 1485).
4. The function returns early at line 1487–1489 with zero rewards distributed.
5. Any subsequent call in the same block — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`.
6. The block's reward is permanently lost; it cannot be retroactively claimed.

---

### Impact Explanation

**Permanent freezing of unclaimed yield.**

Block rewards in the consensus phase are computed per-block and credited to `unclaimed_rewards_own` of the staker (and forwarded to pools). If a block's slot is consumed with `disable_rewards: true`, those rewards are never minted or credited. The `last_reward_block` guard prevents any retry for the same block. The `calculate_block_rewards` function does account for missed blocks (multiplying by blocks elapsed since `last_reward_block`), but only when the *next* legitimate call arrives — the attacker can repeat the griefing every block, reducing the multiplier back to 1 each time and continuously zeroing out yield.

This affects:
- Stakers' `unclaimed_rewards_own`
- Delegators' pool rewards (transferred to pool contracts and credited to pool members)

---

### Likelihood Explanation

**High.** The function is publicly callable with no economic barrier. A single transaction per block is sufficient. The attacker needs only to know any valid active staker address (trivially observable on-chain). The attack is profitable for a competing staker who wants to suppress rivals' yield, or for a pure griefing actor. It is executable continuously and indefinitely once consensus rewards are active.

---

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the designated Starkware sequencer address (or a stored sequencer role). For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
```

Alternatively, restrict via the existing roles component (e.g., an `APP_GOVERNOR` or dedicated `SEQUENCER` role) consistent with how other privileged functions are guarded in the contract.

---

### Proof of Concept

```
// Consensus rewards are active (post consensus_rewards_first_epoch).
// Staker S is active with non-zero balance.
// Attacker A is any EOA.

Block N arrives:
  A calls: staking.update_rewards(staker_address: S, disable_rewards: true)
    → general_prerequisites() passes (not paused)
    → block_number (N) > last_reward_block (N-1) → passes
    → staker S exists and is active → passes
    → last_reward_block.write(N)          ← slot consumed
    → disable_rewards == true → return    ← no rewards distributed

Sequencer calls: staking.update_rewards(staker_address: S, disable_rewards: false)
    → block_number (N) > last_reward_block (N) → FALSE
    → REWARDS_ALREADY_UPDATED panic        ← legitimate call blocked

Block N's rewards are permanently lost.
A repeats this every block → all consensus-phase yield is frozen.
```

**Root cause:** `src/staking/staking.cairo` lines 1449–1485 — `StakingRewardsManagerImpl::update_rewards` writes `last_reward_block` without verifying the caller is the authorized sequencer. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1447-1489)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );

            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** docs/spec.md (L1626-1652)
```markdown
### update_rewards
```rust
fn update_rewards(ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool);
```
#### description <!-- omit from toc -->
Calculate and update the current block rewards for the for the given `staker_address`.
Send pool rewards to the pools.
Distribute rewards only if `disable_rewards` is False and consensus rewards already started.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
```
