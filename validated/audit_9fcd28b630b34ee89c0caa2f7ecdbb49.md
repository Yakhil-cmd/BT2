### Title
Unrestricted `update_rewards` with Attacker-Controlled `disable_rewards` Allows Permanent Griefing of Consensus Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `Staking` contract is publicly callable by any non-zero address and accepts a caller-controlled `disable_rewards: bool` parameter. An attacker can call this function with `disable_rewards: true` to advance the global `last_reward_block` checkpoint without distributing any rewards, permanently blocking legitimate consensus reward distribution for that block. Because `last_reward_block` is a single global variable, one call per block is sufficient to deny rewards to all stakers.

### Finding Description
`update_rewards` is exposed as a public ABI function with no role-based access control — only `general_prerequisites()` is called, which checks the contract is unpaused and the caller is non-zero. [1](#0-0) 

Inside the function, `last_reward_block` is written to storage **before** the `disable_rewards` branch is evaluated: [2](#0-1) 

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
```

The guard that prevents double-rewarding in the same block is: [3](#0-2) 

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

Because `last_reward_block` is a **single global** storage slot shared across all stakers: [4](#0-3) 

an attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in block N will:
1. Pass the `current_block_number > last_reward_block` guard.
2. Write `last_reward_block = N`.
3. Return early — no rewards are computed or transferred.

Any subsequent legitimate call to `update_rewards(staker, false)` in the same block N will revert with `REWARDS_ALREADY_UPDATED`. The attacker only needs to supply any currently-active staker address with non-zero balance (trivially discoverable on-chain) to satisfy the validity checks: [5](#0-4) 

### Impact Explanation
`last_reward_block` is global. A single attacker transaction per block denies **all** stakers their consensus block rewards for that block. Repeated across every block, this constitutes **permanent freezing of unclaimed yield** — a High-severity impact under the allowed scope. Even sporadic execution constitutes targeted, costless-to-the-attacker yield denial.

### Likelihood Explanation
The function is fully public with no access control. The only prerequisite is knowing any active staker address, which is trivially available from on-chain events (`NewStaker`). On Starknet, transaction fees are low, making sustained griefing economically viable. Likelihood: **Medium**.

### Recommendation
Restrict `update_rewards` to be callable only by an authorized role (e.g., the consensus/block-proposer role), or remove the externally-supplied `disable_rewards` parameter entirely and derive the disable condition internally (e.g., from `is_pre_consensus()` or staker eligibility checks already present in the function body).

### Proof of Concept
1. Attacker observes block N is being produced.
2. Attacker submits `staking.update_rewards(active_staker_address, disable_rewards: true)` with higher fee to front-run the legitimate consensus call.
3. `last_reward_block` is set to N; function returns early — zero rewards distributed.
4. Legitimate consensus call `update_rewards(staker, false)` in block N reverts: `REWARDS_ALREADY_UPDATED`.
5. Stakers receive no block rewards for block N.
6. Attacker repeats every block → all consensus rewards are permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1447-1452)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1460-1483)
```text
            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
