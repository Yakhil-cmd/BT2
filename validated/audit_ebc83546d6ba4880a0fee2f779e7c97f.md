### Title
Missing Access Control on `update_rewards` Allows Any Caller to Suppress Block Rewards — (`File: src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the `StakingRewardsManagerImpl` is documented in the protocol specification as callable only by the **Starkware sequencer**, but the implementation enforces no such restriction. Any unprivileged caller can invoke it with `disable_rewards: true`, consuming the per-block reward slot and permanently preventing reward distribution for that block across all stakers.

---

### Finding Description

The specification at `docs/spec.md` lines 1644–1645 explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation of `update_rewards` in `src/staking/staking.cairo` only calls `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address: [1](#0-0) 

`general_prerequisites` is defined as: [2](#0-1) 

There is no `only_sequencer` or equivalent role check. The function accepts a user-controlled `disable_rewards: bool` parameter. When `disable_rewards` is `true`, the function:

1. Writes `current_block_number` to the global `last_reward_block` storage slot (line 1485), consuming the block's reward slot.
2. Returns early without distributing any rewards (line 1487–1489).

Because `last_reward_block` is a **single global variable** (not per-staker), any subsequent call to `update_rewards` in the same block — including the legitimate sequencer call — will revert with `REWARDS_ALREADY_UPDATED`: [3](#0-2) 

The `last_reward_block` storage field: [4](#0-3) 

The spec's access control requirement: [5](#0-4) 

---

### Impact Explanation

An attacker who front-runs the sequencer's `update_rewards` call with `disable_rewards: true` causes **all stakers** to lose their block rewards for that block. Since `last_reward_block` is global, one call per block is sufficient to suppress rewards for every staker in the system. Repeated across many blocks, this constitutes **permanent freezing of unclaimed yield** for all stakers and their delegators.

This maps to the allowed impact: **Theft of unclaimed yield / Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The function is publicly callable with no role restriction. On Starknet, a malicious actor can monitor the mempool and submit a front-running transaction with `disable_rewards: true` before the sequencer's legitimate call. The attacker has no cost beyond gas and gains nothing financially — this is a pure griefing attack. The attack is repeatable every block.

---

### Recommendation

Add a sequencer-only access control guard to `update_rewards`, consistent with the specification. For example, introduce a `only_rewards_manager` or `only_sequencer` role check (analogous to the existing `only_security_agent` / `only_token_admin` patterns used elsewhere in the contract), and assert it at the top of `update_rewards` before any state changes.

---

### Proof of Concept

1. Staker stakes and K epochs pass — staker is now eligible for consensus block rewards.
2. Attacker (any address) calls `update_rewards(staker_address, disable_rewards: true)` in block N.
3. `last_reward_block` is set to N; function returns early — no rewards distributed.
4. Sequencer attempts `update_rewards(staker_address, disable_rewards: false)` in the same block N.
5. Call reverts with `REWARDS_ALREADY_UPDATED` — staker receives zero rewards for block N.
6. Attacker repeats every block, permanently suppressing all staker and delegator rewards.

The flow test at `src/flow_test/test.cairo` lines 2806–2917 already demonstrates that calling `update_rewards` with `disable_rewards: true` followed by a second call in the same block panics with `REWARDS_ALREADY_UPDATED`, confirming the global slot is consumed. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1489)
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
```

**File:** src/staking/staking.cairo (L1794-1797)
```text
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/flow_test/test.cairo (L2806-2830)
```text
#[test]
#[feature("safe_dispatcher")]
fn update_rewards_disable_rewards_consensus_rewards_flow_test() {
    let cfg: StakingInitConfig = Default::default();
    let mut system = SystemConfigTrait::basic_stake_flow_cfg(:cfg).deploy();
    let stake_amount = system.staking.get_min_stake();
    let staker = system.new_staker(amount: stake_amount);
    let commission = 200;
    system.stake(:staker, amount: stake_amount, pool_enabled: false, :commission);
    system.advance_k_epochs();

    // Disable rewards = true with consensus off - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: true);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
    advance_block_number_global(blocks: 1);
```
