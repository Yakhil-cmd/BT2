### Title
Unprivileged Caller Can Suppress Block Reward Distribution via Caller-Controlled `disable_rewards` Parameter - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is publicly callable with no access control. It accepts a caller-controlled `disable_rewards: bool` parameter. When set to `true`, the function writes the current block number into the global `last_reward_block` storage slot **before** checking `disable_rewards`, then returns early without distributing rewards. This permanently blocks any legitimate reward distribution for that block for all stakers.

### Finding Description
`update_rewards` is exposed via the `IStakingRewardsManager` public interface with no caller restriction beyond the standard `general_prerequisites()` check (contract not paused, caller not zero).

The critical ordering in the implementation is:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← written unconditionally

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← exits without distributing
}
``` [1](#0-0) 

`last_reward_block` is a **single global** storage slot, not per-staker:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

Any subsequent call to `update_rewards` at the same block number will fail the guard:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

Because `last_reward_block` is global, a single call with `disable_rewards: true` for **any** valid staker poisons the slot for **all** stakers for that block. The attacker does not need to target a specific staker.

The function is part of the public ABI with no role check:

```cairo
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();
``` [4](#0-3) 

The interface definition confirms it is fully public:

```cairo
pub trait IStakingRewardsManager<TContractState> {
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
``` [5](#0-4) 

### Impact Explanation
An attacker calling `update_rewards(any_valid_staker, true)` once per block permanently discards the block reward for that block for every staker in the protocol. Repeated every block, this freezes all consensus-era block rewards indefinitely. This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators.

### Likelihood Explanation
The attack requires no special privilege, no capital, and no coordination. The only cost is gas per block. Any adversary (competing validator, griefing bot, or disgruntled user) can execute it. The entry path is a single public function call with a boolean flag.

### Recommendation
1. **Remove the `disable_rewards` parameter from the public interface.** The pre-consensus early-return is already handled by `self.is_pre_consensus()` inside the function body; the external boolean is redundant and dangerous.
2. If `disable_rewards` must remain, gate it behind a privileged role (e.g., `only_security_agent`) so only a trusted caller can suppress distribution.
3. Alternatively, move the `last_reward_block.write(current_block_number)` call to **after** the `disable_rewards` guard so that a suppressed call does not consume the block slot.

### Proof of Concept
1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker calls `staking.update_rewards(any_active_staker, disable_rewards: true)` at block N.
3. `last_reward_block` is written to N; the function returns without distributing rewards.
4. A legitimate caller (staker, keeper, or protocol bot) calls `update_rewards(staker, false)` at block N — the call reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers lose block N rewards permanently.
6. Attacker repeats step 2 at every subsequent block, continuously suppressing all block rewards across the entire protocol.

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

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

**File:** src/staking/interface.cairo (L304-311)
```text
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
