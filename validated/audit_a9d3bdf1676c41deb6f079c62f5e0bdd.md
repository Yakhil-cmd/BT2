### Title
Unprivileged Caller Can Pass `disable_rewards=true` to `update_rewards`, Permanently Blocking Consensus Reward Distribution - (File: src/staking/staking.cairo)

---

### Summary

`update_rewards` in the Staking contract enforces a single-call-per-block invariant via a global `last_reward_block`. It accepts a public `disable_rewards: bool` parameter with no access control. When called with `disable_rewards=true`, it writes `last_reward_block` to the current block but returns early without distributing any rewards. Any unprivileged caller can invoke this every block, consuming the single allowed slot and permanently starving all stakers of consensus rewards.

---

### Finding Description

`update_rewards` is an `#[abi(embed_v0)]` public function gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero — no role restriction exists. [1](#0-0) 

The function enforces a global one-call-per-block invariant: [2](#0-1) 

After validating the staker, it unconditionally writes `last_reward_block`: [3](#0-2) 

Then it checks `disable_rewards` and returns early if true, skipping all reward computation and distribution: [4](#0-3) 

Because `last_reward_block` is a **single global field** (not per-staker), one call with `disable_rewards=true` blocks every other staker from receiving rewards in that block. Any subsequent legitimate call in the same block fails with `REWARDS_ALREADY_UPDATED`. [5](#0-4) 

---

### Impact Explanation

An attacker calling `update_rewards(any_valid_staker, disable_rewards=true)` once per block permanently prevents all stakers from accumulating consensus rewards. This constitutes **permanent freezing of unclaimed yield** for the entire protocol during the consensus rewards phase. The attacker needs only a valid (active, non-zero-balance) staker address, which is publicly observable on-chain.

---

### Likelihood Explanation

High. The entry point is fully public, requires no privileged role, and the only prerequisite is supplying any active staker address. Gas costs on Starknet are low, making a sustained per-block griefing campaign economically feasible. The attacker has no profit motive but causes severe, protocol-wide damage.

---

### Recommendation

Add an access-control check to `update_rewards` restricting callers to an authorized role (e.g., the consensus sequencer or a dedicated `REWARDS_MANAGER` role). Alternatively, remove the `disable_rewards` parameter from the public interface and handle the skip-rewards logic internally based on on-chain conditions that cannot be spoofed by an external caller.

---

### Proof of Concept

1. Consensus rewards are active: `is_pre_consensus()` returns `false`.
2. Attacker identifies any active staker `S` with non-zero STRK balance (public on-chain).
3. At the start of each block, attacker calls `update_rewards(S, disable_rewards=true)`.
4. `last_reward_block` is set to the current block number; no rewards are distributed.
5. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeated every block → all stakers receive zero consensus rewards indefinitely. [6](#0-5)

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
