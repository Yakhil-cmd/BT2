### Title
Missing Caller Restriction on `update_rewards()` Allows Any Address to Permanently Freeze Per-Block Staker Rewards - (File: `src/staking/staking.cairo`)

### Summary
`StakingRewardsManagerImpl::update_rewards()` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` each block, advancing the global `last_reward_block` without distributing rewards, permanently denying all stakers their per-block yield for that block.

### Finding Description
The spec for `update_rewards` explicitly states:

> **Access control:** Only starkware sequencer.

However, the implementation in `src/staking/staking.cairo` at `StakingRewardsManagerImpl` performs no caller identity check whatsoever:

```cairo
// src/staking/staking.cairo lines 1447-1507
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();                          // only checks pause
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        // ... staker existence checks ...

        // *** last_reward_block is written BEFORE the disable_rewards branch ***
        self.last_reward_block.write(current_block_number);   // line 1485

        if disable_rewards || self.is_pre_consensus() {
            return;                                           // line 1488 - exits with NO rewards
        }
        // ... reward distribution ...
    }
}
```

The critical ordering is:
1. `last_reward_block` is unconditionally updated to the current block number (line 1485).
2. If `disable_rewards == true`, the function returns immediately without distributing any rewards (line 1487-1489).
3. The `REWARDS_ALREADY_UPDATED` guard (line 1454-1458) then prevents any subsequent call in the same block, including the legitimate sequencer call.

`last_reward_block` is a **global** storage variable, not per-staker. A single call with any valid `staker_address` and `disable_rewards: true` blocks reward distribution for **all** stakers for that block.

### Impact Explanation
An attacker calling `update_rewards(any_active_staker, disable_rewards: true)` once per block:
- Advances `last_reward_block` to the current block with zero rewards distributed.
- The sequencer's subsequent call for the same block reverts with `REWARDS_ALREADY_UPDATED`.
- Rewards for that block are permanently lost — they are never minted/distributed and cannot be retroactively recovered.
- This maps directly to **High: Permanent freezing of unclaimed yield**, as stakers and pool members lose all per-block consensus rewards indefinitely.

### Likelihood Explanation
The function is publicly callable with no authentication. The attacker only needs to know any active staker address (readable from on-chain events) and call once per block. Gas cost is low. The attack is sustainable indefinitely and requires no privileged access, leaked keys, or external dependencies.

### Recommendation
Add a sequencer-only caller check at the top of `update_rewards`, analogous to the pattern used in `update_unclaimed_rewards_from_staking_contract` and `claim_rewards` in `reward_supplier.cairo`:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ...
}
```

### Proof of Concept
1. Consensus rewards are active (`is_pre_consensus()` returns false).
2. Attacker observes any active staker address `S` from chain events.
3. Each block, attacker calls `staking.update_rewards(S, disable_rewards: true)`.
4. `last_reward_block` is set to the current block; no rewards are distributed.
5. Sequencer calls `staking.update_rewards(S, disable_rewards: false)` → reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers and pool members receive zero rewards for every block the attacker front-runs.

**Root cause lines:** [1](#0-0) [2](#0-1) 

**Spec mandating sequencer-only access (violated):** [3](#0-2)

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

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
