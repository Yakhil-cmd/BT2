### Title
Unprivileged Caller Can Permanently Freeze Block Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards` boolean with no access control. When called with `disable_rewards: true`, the function writes the current block number to the contract-wide `last_reward_block` storage slot **before** checking the flag, then returns without distributing any rewards. Because `last_reward_block` gates all reward updates for the entire contract, any unprivileged address can call this once per block to permanently prevent every staker from receiving consensus-phase block rewards.

### Finding Description
`update_rewards` is exposed as a public function under `IStakingRewardsManager`. Its only entry guard is `general_prerequisites()`, which checks the contract is not paused and the caller is non-zero — no role or identity check is performed. [1](#0-0) 

Inside the function, `last_reward_block` is unconditionally written to the current block number **before** the `disable_rewards` branch is evaluated: [2](#0-1) 

The guard that prevents a second call in the same block reads this same slot: [3](#0-2) 

Because `last_reward_block` is a single contract-wide value (not per-staker), one call with `disable_rewards: true` for **any** valid staker exhausts the reward slot for the entire block. Any subsequent call — including the legitimate one that would distribute rewards — reverts with `REWARDS_ALREADY_UPDATED`.

The pre-consensus analogue (`update_rewards_from_attestation_contract`) is correctly restricted to the attestation contract: [4](#0-3) 

No equivalent restriction exists on `update_rewards`.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block prevents every staker in the protocol from ever accumulating consensus-phase block rewards. The `unclaimed_rewards_own` field of every staker remains at zero indefinitely. Because the attack is repeatable at the cost of a single cheap transaction per block, the freeze is effectively permanent for as long as the attacker is willing to pay gas.

### Likelihood Explanation
**Medium.** The call requires no privileged role, no token balance, and no special setup — only a valid (active, non-zero-balance) staker address to pass the sanity checks. The attacker has no profit motive, but the barrier to execution is extremely low. In a live network the attacker simply needs to submit one transaction per block ahead of any legitimate reward-distribution call.

### Recommendation
Restrict `update_rewards` to a trusted caller (e.g., the attestation contract or a designated keeper role), mirroring the access control already applied to `update_rewards_from_attestation_contract`. Alternatively, move the `self.last_reward_block.write(current_block_number)` assignment to **after** the `disable_rewards` guard so that a no-op call does not consume the block's reward slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;   // do NOT write last_reward_block here
}
self.last_reward_block.write(current_block_number);
// ... distribute rewards
```

### Proof of Concept
1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker picks any currently active staker address `S` with non-zero STRK balance.
3. At the start of block `N`, attacker calls `update_rewards(S, disable_rewards: true)`.
4. `last_reward_block` is written to `N`; the function returns without distributing rewards.
5. The legitimate call `update_rewards(attesting_staker, false)` — whether from the attestation contract or any keeper — reverts with `REWARDS_ALREADY_UPDATED` because `current_block_number == last_reward_block`.
6. Attacker repeats step 3 for every subsequent block.
7. `unclaimed_rewards_own` for all stakers remains zero; no staker can ever claim consensus-phase block rewards.

### Citations

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
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
