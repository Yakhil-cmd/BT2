### Title
Unprivileged Caller Can Permanently Deny All Consensus Block Rewards via `update_rewards(disable_rewards=true)` — (`src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` has **no caller access control**. Any EOA can call it with `disable_rewards=true` each block, consuming the single global `last_reward_block` slot and preventing the legitimate sequencer call (`disable_rewards=false`) from ever distributing consensus rewards.

---

### Finding Description

The spec documents `update_rewards` as restricted to "Only starkware sequencer," but the implementation enforces no such check.

The full function body is: [1](#0-0) 

The only guards are:
1. `self.general_prerequisites()` — checks contract-is-paused only (no caller check; the word "sequencer" does not appear anywhere in `staking.cairo`).
2. `current_block_number > self.last_reward_block.read()` — one-call-per-block gate. [2](#0-1) 

`last_reward_block` is a **single global storage variable** (not per-staker). The first successful call in any block writes it: [3](#0-2) 

Immediately after the write, if `disable_rewards == true`, the function returns without distributing anything: [4](#0-3) 

**Attack sequence per block N:**
1. Attacker calls `update_rewards(any_valid_active_staker, disable_rewards=true)`.
2. `last_reward_block` is set to N; no rewards distributed.
3. Legitimate sequencer call `update_rewards(staker, disable_rewards=false)` at block N hits `current_block_number > last_reward_block` → `N > N` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.

The existing test suite inadvertently documents this exact behavior: [5](#0-4) 

The test at lines 2882–2893 shows `disable_rewards=true` consuming the block slot, then the `disable_rewards=false` call reverting — called from an unprivileged test address with no special role setup.

---

### Impact Explanation

- **Scope:** All active stakers simultaneously (global `last_reward_block`).
- **Effect:** Every consensus block reward is permanently lost. The attacker calls `update_rewards(any_valid_staker, disable_rewards=true)` once per block. Gas cost is trivial on Starknet. Victim stakers accumulate zero `unclaimed_rewards_own` indefinitely.
- **Matches allowed impact:** High — Theft/permanent freezing of unclaimed yield.

---

### Likelihood Explanation

- No privileged role, no leaked key, no bridge dependency required.
- Callable by any EOA with a valid staker address (publicly readable from chain state).
- One transaction per block is sufficient to suppress all rewards for all stakers.
- Economically rational for a competing validator or any griefing actor.

---

### Recommendation

Add a sequencer-only guard at the top of `update_rewards`, consistent with the spec's stated access control:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        starknet::get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::ONLY_SEQUENCER,
    );
    // ... rest of function
}
```

Alternatively, if the sequencer address is not stored, use `starknet::get_execution_info().block_info.sequencer_address` (available in Cairo/Starknet syscalls) to validate the caller is the block proposer.

---

### Proof of Concept

```cairo
// Precondition: consensus rewards active (is_pre_consensus() == false)
// victim_staker: any valid active staker address

for block in 0..N {
    advance_block();
    // Attacker (any EOA) calls first:
    staking_rewards_dispatcher
        .update_rewards(staker_address: victim_staker, disable_rewards: true);
    // last_reward_block = current_block; no rewards distributed.

    // Legitimate sequencer call now reverts:
    let result = staking_rewards_dispatcher_safe
        .update_rewards(staker_address: victim_staker, disable_rewards: false);
    assert result == Err(REWARDS_ALREADY_UPDATED);
}

// After N blocks:
let info = staking_dispatcher.staker_info_v1(victim_staker);
assert!(info.unclaimed_rewards_own == 0); // all rewards stolen/frozen
```

### Citations

**File:** src/staking/staking.cairo (L1449-1507)
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
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```

**File:** src/flow_test/test.cairo (L2882-2916)
```text
    // Disable rewards = true with consensus on - no rewards
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
    advance_blocks(blocks: 1, block_duration: AVG_BLOCK_DURATION);

    // Disable rewards = false with consensus on - rewards
    system.update_rewards(:staker, disable_rewards: false);
    let rewards = system.staker_claim_rewards(:staker);
    let (expected_rewards, _) = calculate_staker_strk_rewards_with_balances_v3(
        amount_own: stake_amount,
        pool_amount: Zero::zero(),
        :commission,
        minting_curve_contract: system.minting_curve.address,
    );
    assert!(expected_rewards.is_non_zero());
    assert!(rewards == expected_rewards);

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: false);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
```
