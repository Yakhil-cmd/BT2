### Title
Unrestricted `disable_rewards` Flag in `update_rewards` Allows Any Caller to Block Consensus Reward Distribution for All Stakers — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable with no meaningful access control. It accepts a `disable_rewards: bool` parameter that, when `true`, advances the global `last_reward_block` checkpoint without distributing any rewards. Because the contract enforces a strict "one update per block" invariant on `last_reward_block`, any unprivileged caller can consume every block's reward slot by repeatedly calling `update_rewards(any_valid_staker, disable_rewards=true)`, permanently denying all stakers their consensus-era block rewards.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks for pause state and a non-zero caller — no role or ownership check exists. [1](#0-0) 

The function first validates that the current block has not yet been processed: [2](#0-1) 

It then validates the staker is active with non-zero balance, and **unconditionally** writes `current_block_number` to `last_reward_block` before checking `disable_rewards`: [3](#0-2) 

When `disable_rewards` is `true`, the function returns immediately after writing `last_reward_block`, distributing nothing. Any subsequent call to `update_rewards` in the same block fails with `REWARDS_ALREADY_UPDATED` because `current_block_number > last_reward_block` is now false.

The `last_reward_block` is a single global slot — not per-staker — so consuming it blocks **all** stakers from receiving rewards in that block: [4](#0-3) 

An attacker needs only a valid, active staker address (trivially obtained from `NewStaker` events or the public `stakers` vector) and calls `update_rewards(victim_staker, true)` in every block. The attack is fully automatable.

---

### Impact Explanation

This is a **High** impact finding: **Permanent/indefinite freezing of unclaimed yield**.

All stakers in the consensus-rewards era (`is_pre_consensus() == false`) are denied block rewards for every block the attacker maintains the attack. The `unclaimed_rewards_own` field in each staker's info never increases, and pool members never receive their share. The attacker has no profit motive but inflicts severe, sustained damage on every participant in the protocol. [5](#0-4) 

---

### Likelihood Explanation

**High.** The attack requires:
1. Any valid active staker address — publicly readable from the `stakers` Vec or emitted `NewStaker` events.
2. One transaction per block — trivially automatable.
3. No privileged access, no leaked keys, no external dependencies.

On Starknet, per-transaction gas costs are low, making sustained block-by-block griefing economically feasible for a motivated attacker.

---

### Recommendation

Add caller authorization to `update_rewards`. The simplest fix is to restrict who may pass `disable_rewards: true`:

```cairo
if disable_rewards {
    // Only the staker or their reward address may suppress reward distribution.
    assert!(
        caller == staker_address || caller == staker_info.reward_address,
        "{}",
        Error::UNAUTHORIZED_DISABLE_REWARDS,
    );
}
```

Alternatively, remove the `disable_rewards` parameter from the public ABI entirely and handle the "no-reward update" path through a separate privileged internal or role-gated function.

---

### Proof of Concept

```
Setup:
  - Consensus rewards are active (is_pre_consensus() == false).
  - Attacker observes any valid active staker address S from on-chain events.

Attack loop (executed every block):
  attacker.call(
      staking_contract.update_rewards(
          staker_address = S,
          disable_rewards = true
      )
  )

Effect per block:
  1. last_reward_block is set to current_block_number.
  2. No rewards are computed or distributed (early return at line 1487).
  3. Any legitimate call to update_rewards in the same block reverts
     with REWARDS_ALREADY_UPDATED (line 1455-1458).

Result:
  - All stakers' unclaimed_rewards_own remains frozen.
  - All pool members' cumulative_rewards_trace is never updated.
  - Unclaimed yield is permanently withheld for the duration of the attack.
```

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

**File:** src/staking/staking.cairo (L2362-2362)
```text
            staker_info.unclaimed_rewards_own += staker_rewards;
```
