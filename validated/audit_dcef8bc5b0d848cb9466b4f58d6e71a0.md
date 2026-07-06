### Title
Unprivileged Caller Can Permanently Suppress Per-Block Consensus Rewards via `disable_rewards: true` — (File: `src/staking/staking.cairo`)

### Summary
The public `update_rewards` function in `StakingRewardsManagerImpl` accepts a caller-controlled `disable_rewards: bool` parameter with no access-control check. Because the global `last_reward_block` counter is written **before** the `disable_rewards` guard, any unprivileged address can call `update_rewards(valid_staker, true)` once per block to permanently consume that block's reward slot without distributing any rewards to stakers.

### Finding Description
`update_rewards` is an `#[abi(embed_v0)]` external function gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero. [1](#0-0) 

The function writes `last_reward_block` to the current block number unconditionally, **then** checks `disable_rewards`: [2](#0-1) 

`last_reward_block` is a single global storage slot shared across all stakers: [3](#0-2) 

Because the guard `current_block_number > self.last_reward_block.read()` is checked at the top of the function, once the slot is consumed for a given block no further call can succeed for that block: [4](#0-3) 

An attacker who calls `update_rewards(any_active_staker, true)` once per block therefore silently discards every block's consensus rewards for the entire protocol.

The `disable_rewards` parameter has no analogous access-control guard anywhere in the function, mirroring the external report's pattern of a critical protection parameter being left unvalidated (hard-coded zero minimum-amount-out there; unchecked `disable_rewards` here).

### Impact Explanation
Every block's STRK (and BTC) consensus rewards are permanently lost — they are never minted/claimed from the reward supplier and never credited to any staker or pool. This constitutes **permanent freezing of unclaimed yield** for all stakers and pool members across the entire protocol, matching the allowed High impact category.

### Likelihood Explanation
The entry point is a fully public external function requiring only a non-zero caller address and a valid (active, non-zero-balance) staker address — both trivially satisfied. The attack costs only gas per block and requires no capital, no privileged role, and no external dependency. Any adversary wishing to grief the protocol or a competitor staker can sustain this indefinitely.

### Recommendation
Add an access-control check so that only a trusted caller (e.g., the attestation contract or a designated rewards-manager role) may invoke `update_rewards`. Alternatively, remove the `disable_rewards` parameter from the public ABI and handle the disable-rewards logic through a separate privileged path. At minimum, the `last_reward_block` write must not occur when `disable_rewards` is `true` and the caller is not authorized.

### Proof of Concept
1. Attacker (any EOA) observes a valid, active staker address `S` with non-zero STRK balance.
2. Each block, attacker calls `update_rewards(S, disable_rewards: true)`.
3. Inside the function:
   - `general_prerequisites()` passes (contract not paused, caller non-zero). [5](#0-4) 
   - Block-number guard passes (new block). [4](#0-3) 
   - Staker validity checks pass. [6](#0-5) 
   - `last_reward_block` is written to current block. [7](#0-6) 
   - `disable_rewards == true` → function returns immediately, no rewards distributed. [8](#0-7) 
4. Any legitimate call to `update_rewards` for the same block now reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers and pool members receive zero consensus rewards for that block. Repeated every block, the entire consensus reward stream is permanently frozen.

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

**File:** src/staking/staking.cairo (L1466-1482)
```text
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
