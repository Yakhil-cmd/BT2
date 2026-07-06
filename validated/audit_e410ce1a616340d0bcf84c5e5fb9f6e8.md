### Title
Unrestricted `disable_rewards` Parameter in `update_rewards` Allows Permanent Freezing of Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards` boolean with no access control. Any unprivileged caller can invoke it with `disable_rewards: true` to consume the single per-block reward slot without distributing any rewards, permanently destroying that block's unclaimed yield for all stakers.

---

### Finding Description

`update_rewards` is a public function gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero. [1](#0-0) 

It accepts two caller-supplied parameters: `staker_address` and `disable_rewards`. [2](#0-1) 

The function enforces a global, single-use-per-block gate via `last_reward_block`: [3](#0-2) 

It then unconditionally writes the current block number to `last_reward_block`: [4](#0-3) 

Finally, if `disable_rewards` is `true`, the function returns immediately without distributing any rewards: [5](#0-4) 

Because `last_reward_block` is a **global** storage variable (not per-staker), only one call to `update_rewards` can succeed per block. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` first in a block:

1. Consumes the per-block slot by writing `last_reward_block = current_block`.
2. Skips all reward distribution.
3. Causes every subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`.

The rewards for that block are permanently lost — they are never accrued to `unclaimed_rewards_own` or forwarded to pool contracts.

This is the direct analog to the reported vulnerability: just as the PixelswapStreamPool accepted a caller-controlled `pair_id` that was never validated against the actual `token_id`, the Staking contract accepts a caller-controlled `disable_rewards` flag that is never validated against any authorization, allowing an attacker to manipulate the reward-distribution state without holding any stake.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker can call `update_rewards` with `disable_rewards: true` at the start of every block, indefinitely. Each such call permanently destroys that block's reward allocation for every staker and every delegation pool. No recovery path exists: once `last_reward_block` is set for a block, no further reward call can succeed for that block. [6](#0-5) 

---

### Likelihood Explanation

**High.** The function is permissionlessly callable by any non-zero address. No stake, no role, and no special condition is required. The attacker only needs to submit a transaction before the legitimate sequencer/validator call in each block. On Starknet, transaction ordering within a block is controlled by the sequencer, but the function itself imposes no caller restriction whatsoever. [7](#0-6) 

---

### Recommendation

- **Short term:** Add an access-control check to `update_rewards` so that only an authorized caller (e.g., the sequencer role, the attestation contract, or a whitelisted address) can invoke it. The `disable_rewards` flag in particular must never be settable by an unprivileged caller.
- **Long term:** Validate all caller-supplied parameters at every public entry point. Parameters that affect global protocol state (such as `last_reward_block`) must be protected by appropriate role checks.

---

### Proof of Concept

1. Attacker (any non-zero EOA or contract) monitors the mempool/block production.
2. At the start of each new block, attacker submits:
   ```
   staking_contract.update_rewards(
       staker_address = <any valid staker>,
       disable_rewards = true
   )
   ```
3. The call passes `general_prerequisites()` (contract not paused, caller non-zero).
4. `current_block_number > last_reward_block` — passes on the first call of the block.
5. `last_reward_block` is written to `current_block_number`.
6. `disable_rewards == true` → function returns without calling `_update_rewards`.
7. All subsequent legitimate calls to `update_rewards` in the same block revert with `REWARDS_ALREADY_UPDATED`.
8. Repeat every block → all consensus block rewards are permanently frozen. [8](#0-7)

### Citations

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
