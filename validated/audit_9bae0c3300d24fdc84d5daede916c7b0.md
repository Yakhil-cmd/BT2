### Title
Unvalidated `disable_rewards` Parameter in Public `update_rewards` Allows Any Caller to Permanently Deny Block Rewards to Stakers - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `IStakingRewardsManager` interface is publicly callable by any address and accepts a caller-controlled `disable_rewards: bool` parameter. When called with `disable_rewards: true`, the function updates `last_reward_block` to the current block but skips reward distribution. Because only one reward update is permitted per block, a front-running attacker can permanently destroy a staker's block rewards for any given block by calling `update_rewards(staker_address, true)` before the staker's legitimate call.

### Finding Description
`update_rewards` is defined in `IStakingRewardsManager` with no access control:

```
fn update_rewards(
    ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
);
```

The implementation at `src/staking/staking.cairo` lines 1448–1507 performs the following unconditionally:

1. Checks `current_block_number > self.last_reward_block.read()` — panics if already updated this block.
2. Validates the staker exists and is active.
3. **Writes `last_reward_block` to the current block** (line 1485) regardless of `disable_rewards`.
4. Then checks `if disable_rewards || self.is_pre_consensus() { return; }` (line 1487) — skipping reward distribution entirely when `disable_rewards` is `true`.

The `last_reward_block` write at line 1485 occurs **before** the `disable_rewards` guard at line 1487. Once `last_reward_block` equals the current block, any subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. The `disable_rewards` input is never validated against any on-chain state — it is accepted verbatim from any caller.

### Impact Explanation
An attacker who front-runs a staker's legitimate `update_rewards(staker_address, false)` call with `update_rewards(staker_address, true)` causes the staker to permanently lose block rewards for that block. The rewards are not deferred — they are destroyed, because `last_reward_block` is consumed without distributing anything. Repeated across many blocks, this constitutes permanent freezing of unclaimed yield for targeted stakers and their delegators.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation
Starknet's public mempool makes front-running feasible. The attacker only needs to submit a transaction with a higher fee in the same block. The attack requires no privileged access, no leaked keys, and no external dependency — only the ability to call a public function. The cost to the attacker is gas per block; the cost to the victim is permanent loss of block rewards.

### Recommendation
Remove the `disable_rewards` parameter from the public interface entirely, or restrict `update_rewards` so that only the staker themselves (or their operational address) can call it. If `disable_rewards` must remain for migration purposes, gate it behind a role check (e.g., `only_app_governor`) or derive the value from on-chain state rather than accepting it as a caller-supplied input.

### Proof of Concept
1. Staker Alice has an active stake and her node is about to call `update_rewards(alice_address, false)` at block N.
2. Attacker Bob observes this in the mempool and submits `update_rewards(alice_address, true)` with a higher fee, landing first in block N.
3. Bob's call: passes the `current_block_number > last_reward_block` check, writes `last_reward_block = N` (line 1485), then returns early at line 1487 without distributing rewards.
4. Alice's call: reverts at line 1454–1457 with `REWARDS_ALREADY_UPDATED` because `last_reward_block == N`.
5. Alice permanently loses block N's rewards. Bob repeats this every block.

**Root cause location:** [1](#0-0) 

**Public interface with no access control:** [2](#0-1)

### Citations

**File:** src/staking/staking.cairo (L1483-1490)
```text

            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

```

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
