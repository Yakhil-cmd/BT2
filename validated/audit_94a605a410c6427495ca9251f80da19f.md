### Title
Unpermissioned `disable_rewards` Flag in `update_rewards` Allows Any Caller to Permanently Suppress Consensus Block Rewards — (File: `src/staking/staking.cairo`)

### Summary
`IStakingRewardsManager::update_rewards` carries a caller-controlled `disable_rewards: bool` parameter and a **global** `last_reward_block` sentinel. Because the function has no access-control guard beyond `general_prerequisites()` (which only rejects the zero address and a paused contract), any unprivileged address can call it with `disable_rewards: true` once per block, consuming the single allowed slot and preventing any legitimate call from distributing rewards for that block. Repeated across every block, this permanently freezes all consensus-era staker yield.

---

### Finding Description

`update_rewards` is the sole entry point for distributing per-block consensus rewards to stakers: [1](#0-0) 

The function's guard logic is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ...
    self.last_reward_block.write(current_block_number);   // global sentinel updated here

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits without distributing rewards
    }
    // ... reward distribution follows
``` [2](#0-1) 

`general_prerequisites` enforces only two conditions: [3](#0-2) 

`last_reward_block` is a **single global** storage slot, not per-staker: [4](#0-3) 

There is **no check** that the caller is the block proposer, the attestation contract, or any other privileged role. The `disable_rewards` flag is entirely attacker-controlled.

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block:

1. `general_prerequisites()` passes (attacker is non-zero, contract is unpaused).
2. The staker existence / activity / non-zero balance checks pass for any live staker.
3. `last_reward_block` is written to the current block number.
4. The function returns early — **no rewards are distributed**.
5. Every subsequent call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.

Because the attacker can repeat this every block at the cost of a single transaction per block, **all stakers permanently lose their consensus-era block rewards**. This maps directly to the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- The function is public with no role restriction.
- The attack requires only a valid (non-zero) staker address, which is publicly observable from `NewStaker` events.
- Cost is one cheap transaction per block; no capital at risk for the attacker.
- The attack is fully automatable and front-runnable against any legitimate `update_rewards` call.

Likelihood: **High**.

---

### Recommendation

Restrict `update_rewards` to a single authorized caller (e.g., the block proposer address registered in the contract, or a dedicated consensus-layer caller role). A minimal fix:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_authorized_rewards_updater(); // add this guard
    // ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface and handle the "no-reward" case internally based on on-chain conditions (e.g., staker did not attest), so the caller cannot influence whether rewards are distributed.

---

### Proof of Concept

```
// Attacker script — run once per block
loop {
    wait_for_new_block();
    staking_contract.update_rewards(
        staker_address = any_live_staker,   // publicly known from events
        disable_rewards = true,
    );
    // last_reward_block is now == current block
    // All legitimate update_rewards calls this block revert with REWARDS_ALREADY_UPDATED
    // No staker receives block rewards for this block
}
```

The attacker pays only gas. Every staker in the protocol loses their consensus block rewards for every block the attacker targets, constituting permanent freezing of unclaimed yield.

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1508)
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
    }
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
