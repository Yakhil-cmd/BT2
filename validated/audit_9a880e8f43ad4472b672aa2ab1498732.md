### Title
Missing Access Control on `update_rewards` Allows Any Caller to Suppress Reward Distribution - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in the Staking contract is documented in the protocol spec as callable "Only starkware sequencer," but the implementation enforces no such restriction. Any unprivileged caller can invoke it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block without distributing any rewards. This permanently blocks the legitimate sequencer from distributing rewards for that block, enabling a continuous griefing attack that freezes unclaimed yield for all stakers and delegators.

### Finding Description
The spec at `docs/spec.md` line 1645 explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation of `update_rewards` in `src/staking/staking.cairo` only calls `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero — no sequencer identity check is performed. [1](#0-0) 

The function accepts a caller-controlled `disable_rewards: bool` parameter. When `true`, the function writes `current_block_number` into the global `last_reward_block` storage slot and returns immediately without distributing any rewards: [2](#0-1) 

`last_reward_block` is a single contract-wide variable: [3](#0-2) 

The guard at the top of `update_rewards` enforces that only one call per block is accepted: [4](#0-3) 

Because `last_reward_block` is global, a single call by any address with `disable_rewards: true` in block N exhausts the per-block slot for **all** stakers. Any subsequent call in block N — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`.

**Attack path:**
1. Attacker monitors the chain for any block in which the sequencer is expected to call `update_rewards`.
2. Attacker submits `update_rewards(any_valid_staker_address, disable_rewards: true)` in the same block, front-running the sequencer.
3. `last_reward_block` is set to the current block; no rewards are distributed.
4. The sequencer's call reverts with `REWARDS_ALREADY_UPDATED`.
5. Stakers and delegators receive zero rewards for that block.
6. Attacker repeats every block.

The only cost to the attacker is Starknet gas per transaction. There is no profit motive required; the attack is pure griefing.

### Impact Explanation
All stakers and delegators lose block rewards for every block in which the attacker front-runs the sequencer. If sustained, this constitutes **permanent freezing of unclaimed yield** for the entire protocol. Even if intermittent, it constitutes **temporary freezing of unclaimed yield**. Both map to the High impact tier in the allowed scope.

### Likelihood Explanation
Any unprivileged address can execute this attack. Valid staker addresses are publicly observable on-chain. Starknet's low gas costs make continuous front-running economically feasible. The attacker needs no special knowledge beyond a live staker address and the ability to submit transactions.

### Recommendation
Add an access-control check at the top of `update_rewards` that asserts the caller is the authorized sequencer address (analogous to `assert_caller_is_attestation_contract` used in `update_rewards_from_attestation_contract`):

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_sequencer(); // enforce "Only starkware sequencer"
    ...
}
``` [5](#0-4) 

Alternatively, split the function into a sequencer-only path (with rewards) and a public no-op path, or store the authorized sequencer address in contract storage and validate it on entry.

### Proof of Concept
```cairo
// Any unprivileged address can call this in every block:
fn grief_rewards(staking: IStakingRewardsManagerDispatcher, victim_staker: ContractAddress) {
    // Attacker calls update_rewards with disable_rewards=true before the sequencer.
    // This sets last_reward_block = current_block_number with zero rewards distributed.
    staking.update_rewards(staker_address: victim_staker, disable_rewards: true);
    // Sequencer's subsequent call in the same block reverts: REWARDS_ALREADY_UPDATED.
    // All stakers earn zero rewards for this block.
}
```

The existing test suite confirms this behavior: `test_update_rewards_without_distribute` (line 3985 of `src/staking/tests/test.cairo`) demonstrates that calling `update_rewards` with `disable_rewards: true` leaves `unclaimed_rewards_own` unchanged, and `test_update_rewards_assertions_before_consensus` (line 3837) confirms that a second call in the same block reverts — regardless of who made the first call. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

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

**File:** src/staking/tests/test.cairo (L3956-3973)
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
