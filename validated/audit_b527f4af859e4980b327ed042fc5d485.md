### Title
Missing Access Control on `update_rewards` Allows Any Caller to Deny Block Rewards to Stakers - (File: src/staking/staking.cairo)

### Summary
`update_rewards` in `staking.cairo` is documented as "Only starkware sequencer" but enforces no caller restriction in code. Any unprivileged address can call it with `disable_rewards: true`, consuming the single per-block reward slot and preventing the sequencer from distributing block rewards for that block. This is a direct analog to the original report's pattern: an unconditional state-transition (`last_reward_block` write) triggered by any external caller during a critical window, with no way for the legitimate party to undo it within the same block.

---

### Finding Description

`update_rewards` is the consensus-phase entry point for distributing per-block staking rewards. Its only guard is a global `last_reward_block` check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // pause check only
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // unconditional write

    if disable_rewards || self.is_pre_consensus() {
        return;                                           // exits without distributing
    }
    ...
``` [1](#0-0) 

The spec documents access control as "Only starkware sequencer": [2](#0-1) 

But no `only_sequencer()` or equivalent role check exists in the implementation. `general_prerequisites()` is a pause-only guard. This is confirmed by unit tests that call `update_rewards` directly with no `cheat_caller_address` setup: [3](#0-2) 

Because `last_reward_block` is a single global storage variable (not per-staker), calling `update_rewards` for **any** `staker_address` with `disable_rewards: true` consumes the entire block's reward slot. The sequencer's subsequent call for the legitimate block producer will revert with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 

---

### Impact Explanation

An attacker who front-runs the sequencer's `update_rewards` call with `disable_rewards: true` causes the block's rewards to be permanently skipped — `unclaimed_rewards_own` is never incremented for the block producer, and the reward supplier's `unclaimed_rewards` is never updated. The yield for that block is permanently lost to the staker. Repeated across many blocks this constitutes **permanent freezing of unclaimed yield** (High) or at minimum sustained **griefing with damage to stakers** (Medium). [5](#0-4) 

---

### Likelihood Explanation

On the current centralized Starknet sequencer, the sequencer controls transaction ordering and can include its own `update_rewards` call as a forced/system transaction before any user transaction. This makes consistent exploitation difficult in the current deployment. However:

1. The code-level access control is entirely absent — the spec's "Only starkware sequencer" is aspirational documentation, not enforced.
2. Any future move toward decentralized sequencing or permissionless block production would make this trivially exploitable.
3. A malicious or compromised sequencer could selectively call `update_rewards(target_staker, disable_rewards: true)` to deny rewards to specific stakers without any on-chain enforcement preventing it.

Likelihood is **Low** under the current centralized sequencer, but the root cause is a real missing access control.

---

### Recommendation

Add an explicit sequencer/operator role check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` enforces `assert_caller_is_attestation_contract`: [6](#0-5) 

Introduce a `only_sequencer()` guard (or reuse an existing role such as `APP_GOVERNOR` or a dedicated `SEQUENCER` role) and call it as the first line of `update_rewards`, before the `last_reward_block` write.

---

### Proof of Concept

1. Consensus rewards are active; staker S is the block producer for block N.
2. Attacker A submits `update_rewards(S, disable_rewards: true)` in block N before the sequencer's call.
3. `last_reward_block` is written to N; function returns early — no rewards distributed.
4. Sequencer attempts `update_rewards(S, disable_rewards: false)` in block N → reverts with `REWARDS_ALREADY_UPDATED`.
5. Staker S receives zero rewards for block N. Repeated every block, S earns nothing. [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L1449-1500)
```text
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
```

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/staking/tests/test.cairo (L3985-4007)
```text
fn test_update_rewards_without_distribute() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let staking_rewards_dispatcher = IStakingRewardsManagerDispatcher {
        contract_address: staking_contract,
    };
    let staking_config_dispatcher = IStakingConfigDispatcher { contract_address: staking_contract };
    stake_for_testing_using_dispatcher(:cfg);
    advance_k_epochs_global();
    let staker_address = cfg.test_info.staker_address;
    let staker_info_before = staking_dispatcher.staker_info_v1(:staker_address);
    // `disable_rewards = true`, and self.is_pre_consensus().
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
    assert!(staker_info_after == staker_info_before);

    // `disable_rewards = false`, and self.is_pre_consensus().
    advance_block_number_global(blocks: 1);
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
    assert!(staker_info_after == staker_info_before);
```
