### Title
Missing Caller Access Control on `update_rewards` Allows Any Address to Suppress Consensus Reward Distribution - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the `Staking` contract is documented in the protocol specification as callable only by the Starkware sequencer, but the implementation contains no caller access control check. Any unprivileged address can call it with `disable_rewards: true`, consuming the single per-block reward slot and permanently preventing consensus reward distribution for all stakers.

### Finding Description

The `IStakingRewardsManager::update_rewards` function is the consensus-era mechanism by which the sequencer distributes per-block STRK and BTC rewards to stakers and their pools. The protocol specification explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation at `src/staking/staking.cairo` lines 1448–1507 contains no `assert_caller_is_sequencer` or equivalent check. The only guard is a per-block mutex:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

After passing this check, the function unconditionally writes `last_reward_block = current_block_number` (line 1485), then branches on the caller-supplied `disable_rewards` flag:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
```

Because `last_reward_block` is a **single global value** (not per-staker), one call per block — for any valid staker — exhausts the slot for the entire block. An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` in every block:

1. Passes all validation (staker exists, is active, has non-zero balance).
2. Advances `last_reward_block` to the current block.
3. Returns immediately without distributing any rewards.
4. Causes every subsequent call in that block — including the legitimate sequencer call — to revert with `REWARDS_ALREADY_UPDATED`.

This is a direct analog to the `nodeIntegration: true` pattern: a capability that should be restricted to a privileged caller is left open to any caller, and the dangerous parameter (`disable_rewards: true`) can be freely supplied by an attacker.

### Impact Explanation

When consensus rewards are active (`is_pre_consensus()` returns `false`), the only path for stakers to accumulate per-block STRK/BTC rewards is through `update_rewards` with `disable_rewards: false`. If an attacker front-runs the sequencer in every block, `unclaimed_rewards_own` for all stakers is never incremented and pool reward traces are never updated. Stakers and delegators permanently lose all consensus-era yield. This matches the allowed impact: **Permanent freezing of unclaimed yield (High)**.

### Likelihood Explanation

Starknet transaction fees are low. The attacker needs to submit one transaction per block targeting any currently active staker. No privileged access, leaked key, or external dependency is required — only a valid staker address (publicly readable from `stakers` storage or events) and sufficient gas. Likelihood: **3 / 5**.

### Recommendation

Add a sequencer-only guard at the top of `update_rewards`, consistent with the specification. The simplest approach is to assert the caller equals the known sequencer address stored in contract configuration, or to introduce a dedicated `SEQUENCER_ROLE` enforced via the existing `RolesComponent`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer(); // add this guard
    self.general_prerequisites();
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface and expose a separate sequencer-only `skip_rewards` path.

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has passed).
2. Attacker observes any active staker address `S` from on-chain events.
3. In every new block `N`, attacker submits:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The call succeeds: `last_reward_block` is set to `N`, function returns early.
5. The sequencer's legitimate call `update_rewards(S, disable_rewards: false)` in block `N` reverts with `REWARDS_ALREADY_UPDATED`.
6. No staker or pool accumulates any consensus rewards for block `N`.
7. Repeated every block → all staker and delegator yield is permanently frozen.

**Key code references:**

- Missing access control: [1](#0-0) 
- Global per-block mutex written unconditionally before the `disable_rewards` branch: [2](#0-1) 
- Specification mandating sequencer-only access: [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1448-1458)
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
