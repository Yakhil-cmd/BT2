### Title
Unchecked `disable_rewards` Parameter in `update_rewards` Allows Permanent Freezing of All Staker Yield - (File: src/staking/staking.cairo)

---

### Summary
`update_rewards` in `staking.cairo` is publicly callable by any address and accepts a user-controlled `disable_rewards` boolean. When `true`, the function unconditionally advances the global `last_reward_block` state variable to the current block without distributing any rewards. Because `last_reward_block` is a single global gate that prevents more than one reward update per block, an attacker can call `update_rewards(any_valid_staker, true)` in every block to permanently prevent all stakers from receiving their consensus-era block rewards.

---

### Finding Description

`update_rewards` (lines 1448–1507 of `src/staking/staking.cairo`) is gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero. No role or identity check restricts who may supply `disable_rewards`. [1](#0-0) 

The function first asserts that the current block has not yet been processed: [2](#0-1) 

It then unconditionally writes the current block number to the global `last_reward_block` storage slot, regardless of `disable_rewards`: [3](#0-2) 

Only after that write does it branch on `disable_rewards`: [4](#0-3) 

The result is a state inconsistency: `last_reward_block` records that block N was processed, yet no rewards were minted or credited to any staker for block N. Because the gate check (`current_block_number > last_reward_block`) now fails for every subsequent call in the same block, no legitimate caller can recover the missed rewards for that block.

The `last_reward_block` storage field is declared as a single global value, not per-staker: [5](#0-4) 

`update_rewards` is the sole reward-distribution path in the consensus-rewards era (`!is_pre_consensus()`). The pre-consensus path (`update_rewards_from_attestation_contract`) explicitly rejects calls once consensus rewards are active: [6](#0-5) 

---

### Impact Explanation

In the consensus-rewards era, every block that passes without a legitimate `update_rewards(staker, false)` call is a block whose rewards are permanently unclaimable. The `reward_supplier` never receives the `update_unclaimed_rewards_from_staking_contract` call, so the accounting is never updated and the STRK/BTC block rewards for that block are never credited to any staker or pool. Repeating the attack across all blocks permanently freezes the entire stream of unclaimed yield for every staker and every delegation pool in the protocol.

---

### Likelihood Explanation

The attack requires only:
1. A valid, active staker address (trivially obtained from on-chain events or `get_stakers`).
2. Calling `update_rewards(staker, true)` once per block.

There is no privilege requirement, no token balance requirement, and no special role. Gas cost is the only barrier, and it is negligible relative to the value of frozen staker rewards across the protocol.

---

### Recommendation

Add an access-control check to `update_rewards` so that only a trusted caller (e.g., the attestation contract, a designated keeper role, or the staker/operational address themselves) may invoke it. Alternatively, remove the `disable_rewards` parameter entirely: if the intent is to allow a no-op update of `last_reward_block`, that path should be restricted to a privileged role. At minimum, `last_reward_block` should not be advanced when `disable_rewards` is `true` and the caller is unprivileged.

---

### Proof of Concept

1. Consensus rewards are active (`!is_pre_consensus()`).
2. Attacker reads any active staker address `S` from on-chain state.
3. In every new block `N`, attacker calls `update_rewards(S, true)`.
4. Inside the call: `current_block_number (N) > last_reward_block` passes → `last_reward_block` is written to `N` → function returns early because `disable_rewards == true`.
5. Any legitimate call to `update_rewards` in block `N` now reverts with `REWARDS_ALREADY_UPDATED`.
6. No staker or pool receives block rewards for block `N`.
7. Repeated every block: all staker yield is permanently frozen. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1394-1403)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

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
