### Title
Unprivileged Caller Can Permanently Freeze Staker Rewards via `update_rewards` with `disable_rewards: true` — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in `src/staking/staking.cairo` has no access control and accepts a caller-controlled `disable_rewards` parameter. The function validates that the current block has not yet been processed (via the global `last_reward_block`), but fails to validate that the caller is authorized or that `disable_rewards` is consistent with the protocol's intent. Any unprivileged address can call `update_rewards(valid_staker, disable_rewards: true)` every block, consuming the global reward slot without distributing any rewards, permanently freezing unclaimed yield for all stakers and delegators.

---

### Finding Description

`update_rewards` is exposed as a public entrypoint with no role restriction: [1](#0-0) 

The only guard is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero: [2](#0-1) 

The protocol specification explicitly states this function should be restricted to "Only starkware sequencer": [3](#0-2) 

The function validates that the current block exceeds `last_reward_block` (one aspect), then **immediately** writes the current block to `last_reward_block` before checking `disable_rewards`: [4](#0-3) 

`last_reward_block` is a **global** (not per-staker) storage variable: [5](#0-4) 

Once updated for a block, all subsequent calls to `update_rewards` for that block revert with `REWARDS_ALREADY_UPDATED`. This means an attacker who calls `update_rewards(valid_staker, disable_rewards: true)` first in a block will:

1. Update `last_reward_block` to the current block.
2. Return early without distributing rewards (line 1487–1489).
3. Block the legitimate sequencer from calling `update_rewards` for that block.

The analog to the MEME404 bug is exact: the code validates one aspect of the call (block not already processed, via `last_reward_block`) but fails to validate a related parameter (`disable_rewards` must be `false` for authorized callers). The same block-number identifier can be "consumed" with `disable_rewards: true` by an attacker when the protocol requires `disable_rewards: false` from the sequencer.

---

### Impact Explanation

By calling `update_rewards(valid_staker, disable_rewards: true)` every block, an attacker permanently prevents reward distribution for all stakers and delegators. Stakers' `unclaimed_rewards_own` is never incremented, and pool rewards are never forwarded to delegation pools via `update_pool_rewards`: [6](#0-5) 

This constitutes **permanent freezing of unclaimed yield** for all protocol participants — a High-severity impact within the allowed scope.

---

### Likelihood Explanation

The attack requires no special permissions, no staked funds, and no privileged access. Any non-zero address can execute it. The only cost is one transaction per block. The attacker does not need to be a staker, delegator, or pool member. The attack is trivially executable and persistent.

---

### Recommendation

Add an access control check to `update_rewards` to restrict it to the authorized sequencer role, consistent with the specification:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer(); // enforce spec: "Only starkware sequencer"
    self.general_prerequisites();
    ...
```

Alternatively, validate that `disable_rewards: true` can only be passed by an authorized role, and that unprivileged callers may only call with `disable_rewards: false` (or not at all).

---

### Proof of Concept

```
1. Deploy the staking contract with a valid staker.
2. Advance K epochs so the staker becomes active.
3. Enable consensus rewards (set_consensus_rewards_first_epoch).
4. Every block, from any non-zero address (e.g., address(1)):
       staking.update_rewards(valid_staker_address, disable_rewards: true)
5. The legitimate sequencer's call:
       staking.update_rewards(valid_staker_address, disable_rewards: false)
   reverts with REWARDS_ALREADY_UPDATED.
6. Staker's unclaimed_rewards_own remains zero indefinitely.
   Pool rewards are never forwarded to delegation pools.
```

This matches the flow test pattern already present in the codebase, which confirms that `disable_rewards: true` suppresses all reward distribution: [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2362-2366)
```text
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
            // Emit event.
```

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/flow_test/test.cairo (L2785-2788)
```text
    // Call update_rewards with disable rewards = true - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards == Zero::zero());
```
