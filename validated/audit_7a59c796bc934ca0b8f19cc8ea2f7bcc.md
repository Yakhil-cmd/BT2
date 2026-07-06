### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Redirect Block Rewards - (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager::update_rewards` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any address can invoke it, choosing which staker receives the block's consensus rewards and permanently consuming the single per-block reward slot.

### Finding Description
The specification at `docs/spec.md` line 1645 explicitly states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1449–1507 enforces none of this. The only guards present are:

1. `general_prerequisites()` — paused check
2. `current_block_number > self.last_reward_block.read()` — one call per block
3. Staker existence and active-status checks

There is no `only_sequencer` function anywhere in the codebase (confirmed by grep), and the `IStakingRewardsManager` interface at `src/staking/interface.cairo` lines 303–311 carries no access-control annotation either.

The function distributes the entire block's consensus rewards to exactly one `staker_address` supplied by the caller, then writes `current_block_number` into `last_reward_block`, permanently preventing any second call in the same block.

### Impact Explanation
**High — Theft / permanent freezing of unclaimed yield.**

An attacker who is a registered staker calls `update_rewards(staker_address: attacker_address, disable_rewards: false)` before the sequencer does. The block's rewards are credited to the attacker's `unclaimed_rewards_own` and the pool sigma index is advanced for the attacker's pool. The sequencer's subsequent call for the legitimately scheduled staker reverts with `REWARDS_ALREADY_UPDATED`. The legitimate staker permanently loses the yield for that block — it is never re-queued or redistributed.

Alternatively, the attacker calls `update_rewards(staker_address: any_valid_staker, disable_rewards: true)`. No rewards are distributed to anyone, yet `last_reward_block` is consumed. Every staker loses that block's yield with zero attacker profit (griefing, Medium).

### Likelihood Explanation
**Medium.** On Starknet the sequencer controls transaction ordering and would normally insert its own `update_rewards` call first. However:

- The sequencer may skip blocks or be temporarily unavailable, leaving the slot open.
- The attacker only needs to submit a transaction in any block where the sequencer has not yet called `update_rewards`.
- No special privilege, leaked key, or external dependency is required — any registered staker address suffices.

### Recommendation
Add a sequencer-only guard at the top of `update_rewards`, analogous to the existing `CALLER_IS_NOT_ATTESTATION_CONTRACT` pattern used in `update_rewards_from_attestation_contract`. Store the expected sequencer address in contract storage (set by governance) and assert `get_caller_address() == sequencer_address` before any other logic.

### Proof of Concept

**Spec (access control requirement):** [1](#0-0) 

**Implementation (no caller check):** [2](#0-1) 

**Interface (no access-control annotation):** [3](#0-2) 

**Reward slot permanently consumed after first call:** [4](#0-3) 

**Rewards credited to attacker-chosen staker:** [5](#0-4) 

Attack steps:
1. Attacker registers as a staker with minimum stake.
2. Each block, before the sequencer acts, attacker calls `update_rewards(staker_address: attacker_address, disable_rewards: false)`.
3. Block rewards are credited to the attacker; `last_reward_block` is set to the current block.
4. Sequencer's `update_rewards` call for the legitimate staker reverts with `REWARDS_ALREADY_UPDATED`.
5. Legitimate staker permanently loses that block's yield.

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
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

**File:** src/staking/staking.cairo (L1484-1488)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
```

**File:** src/staking/staking.cairo (L2349-2362)
```text
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;
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
