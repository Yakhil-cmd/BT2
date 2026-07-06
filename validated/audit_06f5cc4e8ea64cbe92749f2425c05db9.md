### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Deny Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` has no caller restriction. Because it unconditionally writes `last_reward_block = current_block_number` before checking the `disable_rewards` flag, any unprivileged address can call it once per block with `disable_rewards: true` to consume the single allowed call slot without distributing any rewards. The block's yield is then permanently unrecoverable for all stakers.

---

### Finding Description

`update_rewards` is gated only by a "one call per block" guard using the global `last_reward_block` storage variable:

```cairo
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
    ...
    self.last_reward_block.write(current_block_number);   // ← written unconditionally

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits without distributing
    }
    ...
    self._update_rewards(...);
}
``` [1](#0-0) 

`last_reward_block` is a single global field shared across all stakers: [2](#0-1) 

There is no `get_caller_address()` check, no role assertion, and no restriction on who may supply the `disable_rewards` flag. The flow tests confirm the function is invoked without any caller spoofing: [3](#0-2) 

An attacker executes the following in every block during the consensus-rewards phase:

1. Call `update_rewards(any_valid_staker, disable_rewards: true)`.
2. The contract writes `last_reward_block = current_block_number` and returns early.
3. Every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
4. `_update_rewards` is never reached; no STRK is minted or credited to any staker or pool. [4](#0-3) 

The rewards that would have been distributed in that block are permanently lost — `last_reward_block` advances, and there is no catch-up mechanism.

---

### Impact Explanation

This is **permanent freezing of unclaimed yield**. Each block in the consensus-rewards phase produces a fixed STRK reward (`strk_block_rewards`) computed from the minting curve. Once `last_reward_block` is stamped for a block without calling `_update_rewards`, that block's yield is gone forever — it is never credited to `unclaimed_rewards_own` for any staker, and it is never forwarded to any delegation pool. Repeated execution across every block eliminates all consensus-phase staking rewards for the entire protocol. [5](#0-4) 

---

### Likelihood Explanation

The attack requires no special role, no stake, no prior state, and no coordination. Any EOA or contract can call `update_rewards` with an arbitrary valid `staker_address` and `disable_rewards: true`. The only cost is gas per block. The attacker has no profit motive but causes direct, irreversible damage to every staker and delegator in the protocol.

---

### Recommendation

Restrict `update_rewards` to a trusted caller — for example, the block proposer identity supplied by the consensus layer, or a dedicated permissioned sequencer address stored in contract configuration. At minimum, add a role check (e.g., `only_operator` or `only_reward_distributor`) so that the `disable_rewards` flag cannot be weaponized by an arbitrary external caller.

---

### Proof of Concept

```
// Attacker script — run once per block during consensus-rewards phase

let staking = IStakingRewardsManagerDispatcher { contract_address: STAKING };

// Pick any active staker address (readable from public events/storage)
let victim_staker = <any_active_staker>;

loop {
    // Consumes the block's reward slot without distributing anything.
    // No special role or stake required.
    staking.update_rewards(staker_address: victim_staker, disable_rewards: true);

    wait_for_next_block();
}
```

After each call, `last_reward_block` equals the current block number. All subsequent legitimate calls revert with `REWARDS_ALREADY_UPDATED`. The staker's `unclaimed_rewards_own` is never incremented, and no STRK is transferred to any delegation pool for that block. The loss is permanent. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1447-1510)
```text
    #[abi(embed_v0)]
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

    #[generate_trait]
```

**File:** src/staking/staking.cairo (L2348-2376)
```text
            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
            // Emit event.
            self
                .emit(
                    Events::StakerRewardsUpdated {
                        staker_address, staker_rewards, pool_rewards: pool_rewards_list.span(),
                    },
                );

            // Write staker rewards to storage.
            self.write_staker_info(:staker_address, :staker_info);
        }
```

**File:** src/staking/tests/test.cairo (L3514-3516)
```text
    let mut spy = snforge_std::spy_events();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
```
