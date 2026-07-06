### Title
Unprivileged Caller Can Invoke `update_rewards` With `disable_rewards: true` to Permanently Freeze Consensus Block Rewards — (File: src/staking/staking.cairo)

---

### Summary

`update_rewards` is a publicly callable function with no access control beyond a "not paused / caller not zero" check. It accepts a caller-controlled `disable_rewards: bool` parameter. When set to `true`, the function still writes the current block number into the global `last_reward_block` storage slot but returns before distributing any rewards. Because `last_reward_block` is a **global** gate — not per-staker — any non-zero address can consume the reward slot for an entire block without distributing a single token, permanently blocking the consensus contract from distributing rewards in that block.

---

### Finding Description

`update_rewards` is declared in `StakingRewardsManagerImpl` with `#[abi(embed_v0)]`:

```
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
)
``` [1](#0-0) 

The only gate is `general_prerequisites()`, which checks "not paused" and "caller ≠ zero": [2](#0-1) [3](#0-2) 

The function then asserts `current_block_number > last_reward_block` (the global slot), validates the staker, and **unconditionally writes** `current_block_number` into `last_reward_block` before checking `disable_rewards`: [4](#0-3) 

The critical sequence is:

1. `last_reward_block.write(current_block_number)` — slot consumed (line 1485).
2. `if disable_rewards || self.is_pre_consensus() { return; }` — exits without distributing rewards (lines 1487–1489).

Because `last_reward_block` is a **single global variable** (not per-staker), once it is written to block N, every subsequent call to `update_rewards` in block N panics with `REWARDS_ALREADY_UPDATED`. The consensus contract's legitimate call is therefore blocked for the entire block. [5](#0-4) 

The missing validation is: there is no check that the caller is the consensus contract, and there is no check that `disable_rewards` is consistent with any stored per-staker or per-epoch configuration. The parameter is accepted as-is from any caller, directly mirroring the external report's pattern of accepting user-supplied parameters without validating them against stored protocol configuration.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

In the consensus-rewards phase (`is_pre_consensus() == false`), block rewards are distributed once per block via `update_rewards`. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in every block:

- Consumes `last_reward_block` for that block.
- Prevents the consensus contract from distributing STRK block rewards to any staker.
- Causes all stakers' `unclaimed_rewards_own` to remain at zero indefinitely.

Repeated across all blocks, this permanently freezes all unclaimed yield for all stakers in the protocol.

---

### Likelihood Explanation

**High.** The function is fully public. Any non-zero address can call it. The only prerequisite is supplying a valid (active, non-zero-balance) staker address, which is trivially obtained from on-chain `NewStaker` events. No privileged key, bridge access, or external dependency is required.

---

### Recommendation

Restrict `update_rewards` to the consensus contract (or a designated authorized caller). Add an access-control assertion at the top of the function, analogous to how `update_rewards_from_attestation_contract` asserts `assert_caller_is_attestation_contract()`: [6](#0-5) 

A similar guard — e.g., `assert_caller_is_consensus_contract()` — should be added to `update_rewards` before any state is written.

---

### Proof of Concept

1. Attacker reads any active staker address from on-chain `NewStaker` events.
2. In every new block (block N), attacker submits:
   ```
   staking_contract.update_rewards(valid_staker_address, disable_rewards: true)
   ```
3. Inside `update_rewards`:
   - `current_block_number > last_reward_block` passes (new block).
   - Staker validation passes (valid staker).
   - `last_reward_block.write(N)` executes — slot consumed.
   - `disable_rewards == true` → function returns with no rewards distributed.
4. The consensus contract subsequently calls `update_rewards(staker, false)` in block N.
5. `current_block_number > last_reward_block` fails → `REWARDS_ALREADY_UPDATED` panic.
6. No block rewards are distributed for block N.
7. Repeated every block: all stakers' `unclaimed_rewards_own` never increases; all yield is permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1448-1489)
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
