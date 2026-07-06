### Title
Unprivileged Caller Can Freeze Staker Block Rewards via `update_rewards(disable_rewards: true)` — (File: src/staking/staking.cairo)

---

### Summary
The public `update_rewards` function accepts a caller-controlled `disable_rewards` boolean with no access control. Any unprivileged address can invoke it with `disable_rewards: true`, which consumes the global per-block reward slot (`last_reward_block`) while skipping reward distribution entirely. Because only one `update_rewards` call can succeed per block, an attacker who front-runs the legitimate call permanently denies block rewards to stakers.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role or identity check is performed. [1](#0-0) 

The function writes `last_reward_block` to the current block **before** branching on `disable_rewards`: [2](#0-1) 

`last_reward_block` is a single global storage slot shared across all stakers: [3](#0-2) 

The guard at the top of the function enforces that only one call per block can succeed: [4](#0-3) 

Consequence: an attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in block N:
1. Advances `last_reward_block` to N.
2. Returns early — no rewards are calculated or transferred.
3. Any subsequent legitimate call in block N reverts with `REWARDS_ALREADY_UPDATED`.

The attacker only needs a valid, active staker address with non-zero balance, which is trivially obtained from on-chain `NewStaker` events. [5](#0-4) 

---

### Impact Explanation

Each suppressed block distributes zero rewards to the targeted staker and their delegators. Repeated every block, this permanently freezes all unclaimed yield accrual under the consensus rewards model. This maps to **High: Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- No privileged role is required; any EOA or contract can call `update_rewards`.
- The attacker only needs to submit one transaction per block, which is cheap on Starknet.
- Valid staker addresses are publicly observable from `NewStaker` events.
- Front-running is straightforward: the attacker monitors the mempool for legitimate `update_rewards` calls and submits the same call with `disable_rewards: true` at higher priority.

---

### Recommendation

Restrict who may supply `disable_rewards: true`. Options:
1. Add a role check (e.g., `only_app_governor` or a dedicated consensus-caller role) before accepting `disable_rewards: true`.
2. Remove `disable_rewards` from the public ABI and handle the "no-reward" path internally, callable only by the attestation or consensus contract.
3. Move the `last_reward_block.write` to **after** the `disable_rewards` branch so that a disabled call does not consume the block slot.

---

### Proof of Concept

1. Staker A is active with non-zero STRK balance in epoch E.
2. Block N arrives; the consensus mechanism queues `update_rewards(staker_A, false)`.
3. Attacker submits `update_rewards(staker_A, true)` with higher gas priority.
4. Attacker's transaction executes first: `last_reward_block` ← N, function returns early — no rewards distributed.
5. Consensus call executes: `assert!(N > N)` → reverts with `REWARDS_ALREADY_UPDATED`.
6. Staker A and all delegators receive zero rewards for block N.
7. Attacker repeats every block → all future block rewards are permanently frozen. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1507)
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

            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```
