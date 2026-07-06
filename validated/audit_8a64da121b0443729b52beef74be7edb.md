### Title
Any unprivileged caller can grief consensus reward distribution by calling `update_rewards` with `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function is publicly callable by any address. It unconditionally writes the global `last_reward_block` to the current block **before** checking the `disable_rewards` flag. An attacker can call this every block with `disable_rewards: true` to consume the single per-block reward slot without distributing any rewards, permanently preventing all stakers from receiving consensus rewards.

### Finding Description
`update_rewards` in `StakingRewardsManagerImpl` is an `#[abi(embed_v0)]` public function gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role restriction. [1](#0-0) 

The function enforces a global one-update-per-block invariant via `last_reward_block`: [2](#0-1) 

Critically, `last_reward_block` is written to storage **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

This means any caller who supplies a valid, active staker address (publicly available from `NewStaker` events) and passes `disable_rewards: true` will:
1. Pass the `current_block_number > last_reward_block` check.
2. Advance `last_reward_block` to the current block.
3. Return early — zero rewards distributed.

Every subsequent legitimate call to `update_rewards` in that block fails with `REWARDS_ALREADY_UPDATED`. The attacker repeats this every block.

`last_reward_block` is a single global field, not per-staker: [4](#0-3) 

The staker validation the attacker must satisfy is only that the supplied address is active and has non-zero STRK balance at the current epoch — both trivially discoverable on-chain. [5](#0-4) 

### Impact Explanation
This is a sustained griefing attack that causes **temporary (or permanent if sustained) freezing of unclaimed consensus rewards** for every staker in the protocol. No staker can receive block rewards as long as the attacker calls once per block. This matches the allowed impact: *"High: Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds"* and *"Medium: Griefing with no profit motive but damage to users or protocol"*.

### Likelihood Explanation
**Medium.** The attacker must submit one transaction per block. On Starknet, gas costs are low and blocks are frequent, making this economically feasible for a motivated adversary. The only prerequisite is knowing any valid active staker address, which is trivially obtained from on-chain `NewStaker` events.

### Recommendation
1. Move `self.last_reward_block.write(current_block_number)` to after the `disable_rewards` guard, so it is only written when rewards are actually distributed.
2. Alternatively, restrict `update_rewards` so it can only be called by the staker themselves or their registered reward address.
3. Consider making `last_reward_block` per-staker rather than a single global slot.

### Proof of Concept
1. Attacker reads any `NewStaker` event to obtain a valid `staker_address`.
2. On every new block, attacker calls:
   ```
   staking.update_rewards(staker_address: <valid_staker>, disable_rewards: true)
   ```
3. Inside the call: `last_reward_block` is set to `current_block_number`; the function returns early with no rewards distributed.
4. Any legitimate staker or protocol participant who calls `update_rewards` in the same block receives `REWARDS_ALREADY_UPDATED` and their rewards are skipped.
5. Attacker repeats step 2 every block — all consensus-phase stakers are permanently denied block rewards at the cost of one cheap Starknet transaction per block.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1460)
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
