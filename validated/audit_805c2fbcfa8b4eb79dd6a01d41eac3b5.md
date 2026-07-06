### Title
Unprivileged Caller Can Permanently Suppress Consensus Block Rewards for All Stakers via `update_rewards(disable_rewards: true)` — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable with no access control. Any non-zero address can invoke it with `disable_rewards: true`, which advances the global `last_reward_block` sentinel without distributing any rewards. Because `last_reward_block` is a single contract-wide value, this permanently forfeits every staker's block reward for that block and blocks all subsequent legitimate calls for the same block.

---

### Finding Description

`update_rewards` is exposed on the `IStakingRewardsManager` interface with no caller restriction beyond the generic `general_prerequisites` check (contract not paused, caller non-zero). [1](#0-0) 

The function accepts an attacker-controlled `disable_rewards: bool` parameter. Regardless of that flag, the function unconditionally writes the current block number into the global `last_reward_block` storage slot before branching: [2](#0-1) 

When `disable_rewards` is `true`, execution returns immediately after that write, skipping the entire `_update_rewards` call that would credit stakers and pools. [3](#0-2) 

`last_reward_block` is a single global field, not per-staker: [4](#0-3) 

The guard at the top of the function enforces strict monotonicity: [5](#0-4) 

Once an attacker has written the current block number into `last_reward_block` with `disable_rewards: true`, every subsequent call to `update_rewards` for that block — including the legitimate one — reverts with `REWARDS_ALREADY_UPDATED`. The block's rewards are permanently lost; there is no recovery path.

The only prerequisite the attacker must satisfy is supplying a valid active staker address with non-zero balance, which is trivially observable from on-chain events. [6](#0-5) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block permanently destroys that block's consensus rewards for every staker and every delegation pool in the protocol. Repeated every block, this zeroes out all consensus-phase yield indefinitely. The rewards are never minted into `unclaimed_rewards` in the `RewardSupplier`, so they cannot be claimed later. [7](#0-6) 

---

### Likelihood Explanation

**High.** The attack requires no privileged role, no token balance, and no prior relationship with any staker. The attacker only pays gas. Active staker addresses are publicly visible from `NewStaker` events. The attack can be fully automated with a bot that fires one transaction per block. There is no economic barrier.

---

### Recommendation

Restrict `update_rewards` to a single authorized caller (e.g., the consensus sequencer address stored in contract configuration), or split the function so that only a privileged role may pass `disable_rewards: true`. At minimum, the `disable_rewards` path must not be reachable by an arbitrary external caller, because it permanently consumes the per-block reward slot without distributing value.

---

### Proof of Concept

1. Observe any active staker address `S` from on-chain `NewStaker` events.
2. At the first transaction of block `B`, call:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. The contract writes `last_reward_block = B` and returns without calling `_update_rewards`.
4. Any legitimate call `update_rewards(S, false)` in block `B` reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers and pools receive zero rewards for block `B`.
6. Repeat at block `B+1`, `B+2`, … to suppress all consensus rewards indefinitely.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1452)
```text
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

**File:** src/staking/staking.cairo (L1460-1482)
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

**File:** src/staking/staking.cairo (L1484-1507)
```text
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
