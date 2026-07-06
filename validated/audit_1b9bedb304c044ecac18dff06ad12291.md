The key facts from the code:

1. `general_prerequisites()` only checks `assert_is_unpaused()` and `assert_caller_is_not_zero()` — **no sequencer check exists in the implementation**, despite the spec stating "Only starkware sequencer."
2. `last_reward_block` is a **global** (not per-staker) storage variable.
3. Calling with `disable_rewards: true` still writes `last_reward_block` and returns early with zero rewards distributed.

---

### Title
Unprivileged caller can suppress all consensus block rewards by front-running `update_rewards` with `disable_rewards=true` — (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager::update_rewards` is documented as "Only starkware sequencer" but the implementation enforces no such restriction. Any non-zero address can call it. Because `last_reward_block` is a single global variable, one call per block is permitted for the entire protocol. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` first in a block consumes the block's reward slot and distributes nothing, permanently discarding that block's yield for all stakers.

### Finding Description
`StakingRewardsManagerImpl::update_rewards` begins with `self.general_prerequisites()`, which only asserts the contract is unpaused and the caller is non-zero. [1](#0-0) 

There is no role gate, no sequencer check, and no caller validation of any kind in `update_rewards` itself. [2](#0-1) 

The guard `current_block_number > self.last_reward_block.read()` is a **global** per-block gate — it does not track per-staker state. Whichever caller wins the race for a given block number consumes the slot for the entire protocol. [3](#0-2) 

After passing the guard, `last_reward_block` is written unconditionally, before the `disable_rewards` branch: [4](#0-3) 

If `disable_rewards` is `true`, the function returns immediately with no rewards distributed. Any subsequent call in the same block — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`.

The spec explicitly states the access control should be "Only starkware sequencer": [5](#0-4) 

### Impact Explanation
An attacker calling `update_rewards(valid_staker, disable_rewards: true)` at the start of every block permanently discards that block's consensus rewards for all stakers. Because `last_reward_block` is global, no other staker can reclaim the missed block. Rewards are not deferred — they are simply never minted/attributed. This constitutes **permanent freezing of unclaimed yield** (High impact per scope).

### Likelihood Explanation
The call is cheap (no token transfer, no approval needed). Any address can execute it. A griefing attacker needs only to submit a transaction before the sequencer's reward update each block. On Starknet, transaction ordering within a block is controlled by the sequencer, which partially mitigates this — but the sequencer itself is the intended caller, and the missing access control means any external account can race it. A malicious or compromised mempool participant, or even the staker themselves wishing to suppress a competitor's rewards, can exploit this.

### Recommendation
Add a sequencer-only access control check to `update_rewards`, consistent with the spec. For example, assert `get_caller_address() == sequencer_address` where `sequencer_address` is a stored, governance-controlled value, or use Starknet's `get_execution_info` to verify the transaction originates from the expected sequencer account.

### Proof of Concept
1. Deploy two active stakers, `S1` and `S2`, both past the K-epoch activation window with consensus rewards active.
2. At the start of block `N`, attacker calls `update_rewards(S1, disable_rewards: true)`.
   - `last_reward_block` is set to `N`; no rewards distributed.
3. Legitimate sequencer attempts `update_rewards(S1, disable_rewards: false)` — reverts with `REWARDS_ALREADY_UPDATED`.
4. Legitimate sequencer attempts `update_rewards(S2, disable_rewards: false)` — also reverts with `REWARDS_ALREADY_UPDATED` (same global gate).
5. Repeat for every block. Neither staker accumulates any consensus rewards. `staker_claim_rewards` returns zero indefinitely.

The test suite already demonstrates the `REWARDS_ALREADY_UPDATED` gate blocks all subsequent calls in the same block regardless of `staker_address` or `disable_rewards` value: [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
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

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/tests/test.cairo (L3877-3894)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());

    advance_epoch_global();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    // Catch REWARDS_ALREADY_UPDATE - with distribute = false.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
