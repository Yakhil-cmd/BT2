### Title
Unauthorized `update_rewards` Call with `disable_rewards: true` Permanently Freezes Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in the Staking contract has no caller authorization check. Any unprivileged address can call it with `disable_rewards: true` for any valid staker, consuming the global `last_reward_block` slot without distributing rewards. Because `last_reward_block` is a single global value, this permanently prevents all stakers from receiving block rewards for that block. Repeated every block, this permanently freezes all unclaimed yield.

---

### Finding Description

`update_rewards` is exposed on `IStakingRewardsManager` with no restriction on who may call it: [1](#0-0) 

The only gate is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero: [2](#0-1) 

Inside `update_rewards`, the global `last_reward_block` is written **before** the `disable_rewards` branch: [3](#0-2) 

If `disable_rewards: true`, the function returns immediately after writing `last_reward_block`, distributing nothing: [4](#0-3) 

`last_reward_block` is a single global storage slot, not per-staker: [5](#0-4) 

The guard at the top of `update_rewards` enforces that only one call per block succeeds: [6](#0-5) 

Once an attacker's call succeeds in block N, every subsequent call in block N reverts on `REWARDS_ALREADY_UPDATED`. Block N's rewards are permanently unrecoverable.

---

### Impact Explanation

Block rewards are computed per-block and distributed only when `update_rewards` is called in that block. There is no catch-up mechanism: if `last_reward_block` is set to block N without distributing rewards, block N's yield is permanently lost for all stakers and delegators. An attacker calling this every block permanently freezes all unclaimed yield across the entire protocol.

**Impact: High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

The attack requires only:
1. Any valid staker address (trivially obtained from on-chain `NewStaker` events).
2. Gas to submit one transaction per block.

No privileged access, no leaked key, no external dependency. The attacker gains nothing financially, but the protocol suffers total yield loss. On Starknet, per-block transaction costs are low, making sustained griefing economically feasible.

**Likelihood: High.**

---

### Recommendation

Add an authorization check to `update_rewards` so only the attestation contract, the staker's operational address, or another designated caller may invoke it. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    // Add: assert caller is attestation contract or staker's operational address
    let caller = get_caller_address();
    assert!(
        caller == self.attestation_contract.read()
            || caller == self.internal_staker_info(:staker_address).operational_address,
        "{}",
        Error::UNAUTHORIZED_CALLER,
    );
    ...
}
```

Alternatively, move the `last_reward_block.write` to after the `disable_rewards` guard so that a no-op call does not consume the block slot.

---

### Proof of Concept

1. Staker Alice is registered; her address is visible from `NewStaker` events.
2. Attacker (any EOA) calls `update_rewards(staker_address: Alice, disable_rewards: true)` in block N.
3. `last_reward_block` is set to N; function returns early — no rewards distributed.
4. Any legitimate call to `update_rewards` in block N reverts with `REWARDS_ALREADY_UPDATED`.
5. Block N's rewards are permanently lost.
6. Attacker repeats every block → all protocol yield is permanently frozen. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1507)
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
