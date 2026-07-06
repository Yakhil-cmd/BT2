### Title
Unprivileged caller can permanently freeze consensus rewards by front-running `update_rewards` with `disable_rewards: true` — (File: src/staking/staking.cairo)

---

### Summary

The `IStakingRewardsManager::update_rewards` function is publicly callable with no access control. An attacker can call it with `disable_rewards: true` in every block, advancing the global `last_reward_block` checkpoint without distributing any rewards. This permanently blocks the legitimate consensus-mechanism call in the same block, causing all stakers to lose their block rewards.

---

### Finding Description

`update_rewards` is exposed as a public ABI entry-point under `IStakingRewardsManager`. Its only gate is `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role check, no allowlist. [1](#0-0) 

The function accepts a caller-supplied `disable_rewards: bool`. When `true`, it writes the current block number into the **global** `last_reward_block` storage variable and returns immediately, skipping all reward computation: [2](#0-1) 

The guard at the top of the function enforces that only one call per block can succeed: [3](#0-2) 

Because `last_reward_block` is a single global (not per-staker), a single attacker call with `disable_rewards: true` for **any** valid staker in block N:

1. Advances `last_reward_block` to N.
2. Distributes zero rewards.
3. Causes every subsequent `update_rewards` call in block N to revert with `REWARDS_ALREADY_UPDATED`.

The rewards for block N are permanently lost — there is no mechanism to retroactively distribute them for a past block. [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

By repeating the attack every block, an attacker permanently prevents all stakers from accumulating consensus rewards. The rewards are not deferred; they are simply never credited. Stakers' `unclaimed_rewards_own` fields never increase, and pool members never receive their share of block rewards.

---

### Likelihood Explanation

**High.** The function is unconditionally public. The attack costs one cheap Starknet transaction per block. No special privilege, leaked key, or external dependency is required. Any actor with a motive to harm stakers (e.g., a competing validator, a griefing bot) can execute this continuously.

---

### Recommendation

Restrict `update_rewards` to a trusted caller — for example, the operational address of the staker being rewarded, or a dedicated consensus-layer role. The simplest fix is to add a role check (e.g., `only_block_proposer` or `only_operator`) before the `last_reward_block` write, analogous to how `update_rewards_from_attestation_contract` is gated: [5](#0-4) 

Alternatively, remove the `disable_rewards` parameter entirely and let the caller always distribute rewards; handle the "no-reward" case through a separate, access-controlled path.

---

### Proof of Concept

```
// Attacker script (pseudocode, one call per block):
loop every block N:
    staking_contract.update_rewards(
        staker_address = any_active_staker,   // any valid staker passes the guard
        disable_rewards = true,
    )
    // Effect:
    //   last_reward_block := N
    //   no rewards distributed
    //   all subsequent update_rewards calls in block N revert with REWARDS_ALREADY_UPDATED
```

Step-by-step:

1. Attacker picks any active staker address (readable from public events or `get_stakers`).
2. In every block, attacker submits `update_rewards(staker, true)` before the legitimate consensus call.
3. `last_reward_block` is set to the current block; the function returns early.
4. The legitimate call (with `disable_rewards: false`) reverts because `current_block_number > last_reward_block` is now `false`.
5. No staker receives block rewards for that block.
6. Repeated every block → permanent freeze of all consensus-phase unclaimed yield.

### Citations

**File:** src/staking/staking.cairo (L1448-1460)
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
