### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Block Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

The specification mandates that `update_rewards` is callable **only by the Starkware sequencer**, but the implementation enforces no such restriction. Any unprivileged address can call `update_rewards` with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block without distributing any rewards. The sequencer's subsequent call for the same block then reverts with `REWARDS_ALREADY_UPDATED`, permanently destroying that block's yield for all stakers.

---

### Finding Description

The specification at `docs/spec.md` line 1645 states:

```
#### access control
Only starkware sequencer.
```

The implementation at `src/staking/staking.cairo` lines 1449–1507 enforces only `general_prerequisites()`, which checks for pause state and a non-zero caller:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only: not paused + caller != zero
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // Update last block rewards.
    self.last_reward_block.write(current_block_number);   // ← written BEFORE disable check

    if disable_rewards || self.is_pre_consensus() {
        return;   // ← returns without distributing rewards
    }
    ...
```

The critical ordering is:

1. `last_reward_block` is written to `current_block_number` unconditionally (line 1485).
2. Only *after* that write does the function check `disable_rewards` (line 1487).

Because `last_reward_block` is a **single global value** (not per-staker), once any caller sets it to the current block, no further call to `update_rewards` can succeed for that block — they all revert with `REWARDS_ALREADY_UPDATED`. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` in every block where consensus rewards are active. The function:

- Passes all checks (contract unpaused, caller non-zero, staker active, block not yet rewarded).
- Writes `last_reward_block = current_block_number`.
- Returns early without distributing any rewards.

The sequencer's intended call for the same block then reverts. The block's reward allocation is permanently lost — it cannot be retroactively recovered because the reward calculation is block-specific. Repeated across every block, this completely freezes all consensus-era yield for every staker and delegator.

This maps to the allowed impact: **High — Permanent freezing of unclaimed yield**. [4](#0-3) [5](#0-4) 

---

### Likelihood Explanation

- **No privilege required**: any EOA or contract with a non-zero address can call `update_rewards`.
- **No capital at risk**: the attacker only pays gas.
- **Trivially automatable**: a bot can watch the chain and submit the griefing call in every block before the sequencer.
- **Consensus rewards are already active** (or will be once `set_consensus_rewards_first_epoch` is called), making the attack surface live. [6](#0-5) 

---

### Recommendation

Add a sequencer-only access control guard at the top of `update_rewards`, analogous to the existing role checks used elsewhere in the contract (e.g., `only_security_agent`, `only_app_governor`). The simplest approach is to verify `get_caller_address() == sequencer_address` where `sequencer_address` is a stored, governance-controlled value, or to use Starknet's built-in `get_sequencer_address()` syscall. [7](#0-6) 

---

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been reached).
2. Attacker identifies any currently active staker `S` (readable from `get_stakers()`).
3. In block `B`, before the sequencer submits its `update_rewards` transaction, attacker submits:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. Transaction succeeds: `last_reward_block` is set to `B`, no rewards distributed.
5. Sequencer's `update_rewards` call for block `B` reverts with `REWARDS_ALREADY_UPDATED`.
6. Block `B`'s rewards are permanently lost.
7. Repeat for every subsequent block — all staker and delegator yield is frozen indefinitely. [8](#0-7) [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L185-188)
```text
        staker_unstake_intent_epoch: Map<ContractAddress, Epoch>,
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1314-1339)
```text
        fn set_consensus_rewards_first_epoch(ref self: ContractState, epoch_id: Epoch) {
            self.roles.only_app_governor();
            let curr_epoch = self.get_current_epoch();
            assert!(epoch_id >= curr_epoch + 2, "{}", Error::INVALID_EPOCH);
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            // If it's the first time setting the consensus rewards first epoch, initialize block
            // rewards.
            // We use `curr_epoch + 1` to ensure the average is computed only after completing
            // at least one full epoch. This prevents calculating the average over too few blocks,
            // since we are currently mid-epoch. The next calculation will therefore occur after
            // at least one complete epoch (the next epoch) has passed.
            if self.consensus_rewards_first_epoch.read().is_zero() {
                self
                    .calculate_block_rewards(
                        reward_supplier_dispatcher: self.reward_supplier_dispatcher.read(),
                        curr_epoch: curr_epoch + 1,
                    );
            }
            self.consensus_rewards_first_epoch.write(epoch_id);
            self
                .emit(
                    ConfigEvents::ConsensusRewardsFirstEpochSet {
                        consensus_rewards_first_epoch: epoch_id,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L1448-1507)
```text
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

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
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
