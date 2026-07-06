### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Block Reward Distribution - (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in `staking.cairo` is specified as "Only starkware sequencer" but has no on-chain caller enforcement. Because `last_reward_block` is a **global** (not per-staker) storage variable, any unprivileged address can call `update_rewards(staker_address, disable_rewards=true)` once per block to set `last_reward_block` to the current block, causing every subsequent legitimate sequencer call in that block to revert with `REWARDS_ALREADY_UPDATED`. Repeated across every block, this permanently freezes unclaimed yield for all stakers.

---

### Finding Description

`update_rewards` is the consensus-era reward distribution entry point. Its only guard is `general_prerequisites()`, which checks the pause flag but does **not** verify the caller is the Starkware sequencer. [1](#0-0) 

The function writes the global `last_reward_block` to the current block number **before** the `disable_rewards` branch: [2](#0-1) 

When `disable_rewards=true`, the function returns immediately after writing `last_reward_block`, distributing nothing. Any subsequent call in the same block — including the legitimate sequencer call with `disable_rewards=false` — hits:

```
assert!(current_block_number > self.last_reward_block.read(), Error::REWARDS_ALREADY_UPDATED)
```

Because `last_reward_block` is a single scalar (not a per-staker map), one griefing call per block blocks **all** stakers from receiving rewards in that block.

The spec documents the intended restriction: [3](#0-2) 

But the implementation contains no `assert!(get_caller_address() == sequencer_address, ...)` or equivalent role check. The test suite confirms this by calling `update_rewards` without any `cheat_caller_address`: [4](#0-3) 

---

### Impact Explanation

An attacker who calls `update_rewards(any_active_staker, disable_rewards=true)` at the start of every block:

1. Sets `last_reward_block` to the current block.
2. Forces the sequencer's legitimate `update_rewards(..., disable_rewards=false)` call to revert with `REWARDS_ALREADY_UPDATED`.
3. No STRK rewards are credited to any staker or delegation pool for that block.

Sustained across all blocks, this permanently freezes all unclaimed yield for every staker and delegator in the protocol. The attacker gains nothing financially but causes complete denial of the reward mechanism.

**Impact: High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

- The call requires no stake, no special role, and no token approval — only gas.
- The attacker only needs to supply any currently-active staker address (publicly readable via `get_stakers`).
- The attack is fully automatable: one transaction per block, indefinitely.
- There is no on-chain mechanism to distinguish the attacker's call from the sequencer's call.

**Likelihood: High.**

---

### Recommendation

Add an explicit caller check at the top of `update_rewards`, enforcing that only the designated Starkware sequencer address (or a role-gated address) may invoke it, consistent with the specification:

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

Alternatively, move the `last_reward_block.write` to **after** the `disable_rewards` guard so that a no-op call does not consume the block's reward slot.

---

### Proof of Concept

1. Deploy the staking system and advance K epochs so a staker has an active balance.
2. Start consensus rewards (`set_consensus_rewards_first_epoch`).
3. From any EOA (no special role), call:
   ```
   staking.update_rewards(staker_address=<any_active_staker>, disable_rewards=true)
   ```
4. Observe that `last_reward_block` is now set to the current block and no rewards were distributed.
5. The sequencer's call `update_rewards(staker_address, disable_rewards=false)` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeat step 3 every block. All stakers receive zero rewards indefinitely.

The existing test `update_rewards_disable_rewards_consensus_rewards_flow_test` already demonstrates that calling `update_rewards` with `disable_rewards=true` followed by `disable_rewards=false` in the same block produces `REWARDS_ALREADY_UPDATED` — the only missing element is that the first call is made by an attacker rather than the sequencer: [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1447-1458)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/tests/test.cairo (L3877-3884)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
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
