### Title
Missing Access Control on `update_rewards` Allows Anyone to Permanently Freeze All Staker Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the staking contract has no caller access control and exposes a `disable_rewards: bool` parameter to any public caller. An unprivileged attacker can call `update_rewards(any_valid_staker, disable_rewards: true)` every block to consume the global per-block reward slot without distributing any rewards, permanently denying yield to every staker in the consensus era.

### Finding Description
`update_rewards` is implemented under `StakingRewardsManagerImpl` with no `assert_caller` or role check: [1](#0-0) 

The function enforces a single-call-per-block invariant via a **global** (not per-staker) `last_reward_block` storage variable: [2](#0-1) 

It then writes the current block number unconditionally before checking `disable_rewards`: [3](#0-2) 

When `disable_rewards` is `true`, the function returns immediately after updating `last_reward_block`, distributing nothing. Because `last_reward_block` is a single global slot, any call — regardless of which `staker_address` is passed — blocks every other staker from receiving rewards in that block.

The spec confirms the function is intentionally open: [4](#0-3) 

In the consensus era `update_rewards` is the **only** reward path; `update_rewards_from_attestation_contract` is gated by `CONSENSUS_REWARDS_IS_ACTIVE` and reverts once consensus begins: [5](#0-4) 

### Impact Explanation
An attacker calling `update_rewards(any_active_staker, disable_rewards: true)` once per block permanently freezes unclaimed yield for **all** stakers. No staker can recover rewards for any skipped block because `last_reward_block` is already set. This maps directly to the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation
- The function is public with zero access control.
- The attacker only needs to know one valid, active staker address (all staker addresses are on-chain public state).
- The cost is one Starknet transaction per block; Starknet fees are low.
- No special privilege, key, or bridge access is required.

### Recommendation
Restrict `update_rewards` to a trusted caller set (e.g., only the staker themselves, their operational address, or a designated keeper role), consistent with how `update_rewards_from_attestation_contract` is restricted to only the attestation contract: [6](#0-5) 

Alternatively, remove `disable_rewards` from the public interface entirely and handle the pre-consensus no-op path internally.

### Proof of Concept
1. The system enters the consensus era (`consensus_rewards_first_epoch` is reached).
2. Attacker observes the mempool for any `update_rewards(..., disable_rewards: false)` call targeting block N.
3. Attacker front-runs with `update_rewards(any_valid_active_staker, disable_rewards: true)` in block N.
4. `last_reward_block` is written to N; no rewards are distributed.
5. The legitimate call reverts with `REWARDS_ALREADY_UPDATED` — confirmed by the assertion at: [2](#0-1) 

6. All stakers lose rewards for block N. The attacker repeats this every block at negligible cost, achieving permanent yield freeze across the entire protocol.

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

**File:** docs/spec.md (L1139-1165)
```markdown
### update_rewards_from_attestation_contract
```rust
fn update_rewards_from_attestation_contract(ref self: ContractState,
 staker_address: ContractAddress)
```
#### description <!-- omit from toc -->
Calculate and update rewards for the staker for the current epoch.
Send pool rewards to the pool.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [CONSENSUS\_REWARDS\_IS\_ACTIVE](#consensus_rewards_is_active)
3. [CALLER\_IS\_NOT\_ATTESTAION\_CONTRACT](#caller_is_not_attestation_contract)
4. [STAKER\_NOT\_EXISTS](#staker_not_exists)
5. [UNSTAKE\_IN\_PROGRESS](#unstake_in_progress)
#### pre-condition <!-- omit from toc -->
#### access control <!-- omit from toc -->
Only attestation contract.
#### logic <!-- omit from toc -->
1. Calculate total rewards for `staker_address` in this epoch.
2. Calculate staker rewards (include commission).
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer to the pool, if exist.
5. Update `RewardSupplier Contract unclaimed_rewards`.

```
