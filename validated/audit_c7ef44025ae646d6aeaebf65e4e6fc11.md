### Title
Missing Caller Validation in `update_rewards` Allows Any Address to Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` is documented as callable "Only starkware sequencer" but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true` to consume the single global `last_reward_block` slot for the current block, permanently preventing the sequencer from distributing rewards to all stakers for that block. Repeating this every block permanently freezes all unclaimed yield.

### Finding Description

The spec explicitly states the access control for `update_rewards` is "Only starkware sequencer": [1](#0-0) 

However, the implementation only calls `general_prerequisites()`, which checks for pause state and a non-zero caller — no sequencer role check exists: [2](#0-1) 

`general_prerequisites` is: [3](#0-2) 

The function uses a single **global** `last_reward_block` storage variable (not per-staker): [4](#0-3) 

When any caller invokes `update_rewards(any_valid_staker, disable_rewards: true)`:
1. The check `current_block_number > last_reward_block` passes.
2. `last_reward_block` is written to the current block number.
3. The function returns early — **no rewards are distributed**.
4. Any subsequent call in the same block (including the legitimate sequencer call) reverts with `REWARDS_ALREADY_UPDATED`. [5](#0-4) 

Because `last_reward_block` is global, a single attacker call for **any** valid staker blocks reward distribution for **all** stakers in that block.

### Impact Explanation

An attacker calling `update_rewards(staker, disable_rewards: true)` once per block permanently prevents the sequencer from distributing consensus rewards to any staker. Since `unclaimed_rewards_own` is never incremented, all stakers' unclaimed yield is frozen for every block the attacker front-runs. This constitutes **permanent freezing of unclaimed yield** (High impact).

### Likelihood Explanation

The call requires only a valid staker address (publicly readable from events) and a non-zero caller. There is no economic barrier. On Starknet L2, transaction fees are negligible, making sustained block-by-block griefing trivially affordable. The attacker gains nothing financially but can permanently deny all stakers their rewards.

### Recommendation

Add a sequencer-only access control check at the top of `update_rewards`, consistent with the spec. For example, using the existing roles component:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.roles.only_sequencer(); // enforce spec: "Only starkware sequencer"
    ...
}
```

Alternatively, restrict via a dedicated `SEQUENCER_ROLE` assigned to the Starknet sequencer address, mirroring how `only_security_agent` and `only_token_admin` are used elsewhere in the contract. [6](#0-5) 

### Proof of Concept

```
// Attacker script (pseudocode, one call per block):
// 1. Read any active staker_address from NewStaker events.
// 2. Each block, call:
staking.update_rewards(staker_address, disable_rewards: true);
// 3. The sequencer's update_rewards call in the same block reverts with REWARDS_ALREADY_UPDATED.
// 4. No staker accumulates unclaimed_rewards_own for that block.
// 5. Repeat every block → all stakers permanently frozen out of yield.
```

The `REWARDS_ALREADY_UPDATED` guard that is meant to prevent double-distribution becomes the weapon: it is triggered by the attacker before the sequencer, consuming the block's reward slot with zero distribution. [7](#0-6)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1249-1257)
```text
    impl StakingPauseImpl of IStakingPause<ContractState> {
        fn pause(ref self: ContractState) {
            self.roles.only_security_agent();
            if self.is_paused() {
                return;
            }
            self.is_paused.write(true);
            self.emit(PauseEvents::Paused { account: get_caller_address() });
        }
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
