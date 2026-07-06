### Title
Unprivileged Caller Can Permanently Freeze Block Rewards for All Stakers via `update_rewards(disable_rewards: true)` - (File: `src/staking/staking.cairo`)

---

### Summary
The `update_rewards` function in the staking contract updates the global `last_reward_block` checkpoint **before** checking the `disable_rewards` flag. Because the function has no access control beyond "caller is not zero and contract is not paused," any unprivileged caller can invoke it with `disable_rewards: true` every block, consuming each block's reward slot without distributing any rewards. This permanently freezes unclaimed yield for all stakers.

---

### Finding Description

`update_rewards` is the consensus-era entry point for distributing per-block STRK/BTC rewards. Its logic is:

1. Assert `current_block_number > last_reward_block` (one call per block, globally).
2. Validate the staker is active with non-zero balance.
3. **Write `last_reward_block = current_block_number`.**
4. If `disable_rewards || is_pre_consensus()` → **return early, no rewards distributed.**
5. Otherwise, calculate and distribute block rewards. [1](#0-0) 

The critical flaw is that step 3 (the global checkpoint write) occurs **before** step 4 (the early return). Once `last_reward_block` is set to the current block, no other call can distribute rewards for that block — the assertion at step 1 will reject all subsequent calls in the same block. [2](#0-1) 

`last_reward_block` is a **single global storage variable**, not per-staker: [3](#0-2) 

The only access control in `general_prerequisites()` is: [4](#0-3) 

No role check exists. Any non-zero address can call `update_rewards(any_active_staker, disable_rewards: true)`.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` in every block:
- Marks each block as "processed" (`last_reward_block` = current block).
- Skips the actual reward distribution (`_update_rewards` is never reached).
- Prevents every other caller from distributing rewards for that block, because the global `last_reward_block` guard rejects them.

All stakers and their delegation pools lose their block rewards permanently. The rewards are never minted into `unclaimed_rewards` in the `RewardSupplier`, so they are irrecoverable. [5](#0-4) 

---

### Likelihood Explanation

**High.** The attack requires:
- A valid (non-zero) caller address — trivially satisfied.
- Any active staker address with non-zero STRK balance — always available on a live network.
- One transaction per block — feasible and cheap on Starknet.

No privileged role, leaked key, or external dependency is needed.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` / `is_pre_consensus` guard, so the block slot is only consumed when rewards are actually distributed:

```cairo
// Only consume the block slot if rewards will actually be distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Update last block rewards.
self.last_reward_block.write(current_block_number);

// Get current block data and update rewards.
...
```

Alternatively, restrict `update_rewards` to a trusted caller (e.g., the attestation contract or a designated consensus role) so that `disable_rewards: true` cannot be weaponized by arbitrary accounts.

---

### Proof of Concept

1. Staker Alice is active with non-zero STRK balance.
2. Attacker (any EOA) calls `update_rewards(alice, disable_rewards: true)` in block N.
3. `last_reward_block` is set to N; function returns early — no rewards distributed.
4. Alice (or anyone else) calls `update_rewards(alice, disable_rewards: false)` in block N → reverts with `REWARDS_ALREADY_UPDATED`.
5. Block N's rewards are permanently lost for all stakers.
6. Attacker repeats in block N+1, N+2, … — all block rewards are frozen indefinitely. [6](#0-5)

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

**File:** src/staking/staking.cairo (L2348-2365)
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
```
