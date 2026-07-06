### Title
Unprivileged Caller Can Permanently Freeze All Stakers' Consensus Block Rewards via `update_rewards` - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is callable by any unprivileged address. It accepts a `disable_rewards: bool` parameter and unconditionally writes the current block number to the global `last_reward_block` storage slot **before** checking `disable_rewards`. An attacker can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block to advance `last_reward_block` without distributing any rewards, permanently blocking all stakers from receiving consensus block rewards.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero. There is no role-based access control. [1](#0-0) 

The function writes `last_reward_block` to the current block number unconditionally, before the `disable_rewards` guard: [2](#0-1) 

`last_reward_block` is a **single global slot** (not per-staker): [3](#0-2) 

The guard that prevents a second call in the same block reads this global slot: [4](#0-3) 

Because `last_reward_block` is global, a single call to `update_rewards(any_valid_staker, true)` per block exhausts the one allowed call for that block for **every** staker. Any subsequent legitimate call (e.g., from the consensus mechanism with `disable_rewards: false`) reverts with `REWARDS_ALREADY_UPDATED`.

The `disable_rewards` path returns early without distributing rewards: [5](#0-4) 

---

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, true)` on every block permanently prevents all stakers from accumulating consensus block rewards. The rewards for each skipped block are lost forever — they are never credited to `unclaimed_rewards_own` and never forwarded to delegation pools. This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators in the protocol.

---

### Likelihood Explanation

The function is publicly callable with no access control beyond a non-zero caller check. The only cost to the attacker is Starknet gas per block. There is no economic barrier. Any motivated actor — a competitor staker, a protocol adversary, or a griefing bot — can sustain this attack indefinitely.

---

### Recommendation

Restrict `update_rewards` to a designated privileged caller (e.g., the sequencer's designated rewards-distribution address, or a specific role such as `REWARDS_DISTRIBUTOR`). Add a role check at the top of the function analogous to how `update_rewards_from_attestation_contract` restricts its caller: [6](#0-5) 

Alternatively, move the `last_reward_block.write(...)` call to after the `disable_rewards` check so that a call with `disable_rewards: true` from an unauthorized party does not consume the block's reward slot.

---

### Proof of Concept

```
Block N:
  Attacker (any address) calls:
    staking.update_rewards(staker_address=<any_valid_staker>, disable_rewards=true)

  Effect:
    - last_reward_block is set to N
    - No rewards are distributed (early return)

  Legitimate consensus call in same block:
    staking.update_rewards(staker_address=<real_staker>, disable_rewards=false)
    → PANICS: "Rewards already updated for this block"

Repeat every block → all stakers receive zero consensus rewards indefinitely.
```

The attacker requires only a valid (non-zero) staker address to pass the `is_staker_active` check, which is publicly readable from `get_stakers` or events. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1448-1482)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
