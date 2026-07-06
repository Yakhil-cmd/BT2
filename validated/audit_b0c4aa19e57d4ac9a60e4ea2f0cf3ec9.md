### Title
Unprivileged Caller Can Permanently Suppress Block Rewards for All Stakers via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

---

### Summary

`IStakingRewardsManager::update_rewards` is callable by any unprivileged address and accepts a caller-controlled `disable_rewards` boolean. When called with `disable_rewards = true`, the function advances the global `last_reward_block` checkpoint without distributing any rewards. Because the guard `current_block_number > last_reward_block` is now satisfied for no future call in the same block, all stakers permanently lose their consensus block rewards for that block.

---

### Finding Description

`update_rewards` in `src/staking/staking.cairo` has the following structure:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: not-paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ...
    self.last_reward_block.write(current_block_number);   // ← checkpoint advanced unconditionally

    if disable_rewards || self.is_pre_consensus() {
        return;                                           // ← exits before distributing rewards
    }
    // ... actual reward distribution
}
```

`general_prerequisites` only checks that the contract is not paused and the caller is non-zero — there is no restriction on who may call `update_rewards` or what value they may pass for `disable_rewards`. [1](#0-0) [2](#0-1) 

`last_reward_block` is a **single global field** shared across all stakers: [3](#0-2) 

Once an attacker calls `update_rewards(any_staker, disable_rewards: true)` in block `N`, `last_reward_block` is set to `N`. Every subsequent call in block `N` — including legitimate calls from stakers — will revert with `REWARDS_ALREADY_UPDATED`, because the guard `current_block_number > last_reward_block` is no longer satisfied. The rewards for block `N` are permanently lost for every staker in the protocol.

The analog to the external report is direct:

| External (FlashSwapRouter) | This codebase (Staking) |
|---|---|
| Anyone calls `swapRaForDS` with victim's permit | Anyone calls `update_rewards` with any staker address |
| Attacker sets `amountOutMin = 0` | Attacker sets `disable_rewards = true` |
| Victim receives 0 output tokens | All stakers receive 0 block rewards for that block |
| Funds lost via MEV | Yield permanently frozen via griefing |

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block permanently destroys all consensus block rewards for every staker in the protocol for that block. Because `last_reward_block` is global and the per-block guard is a strict inequality, there is no recovery path: the missed rewards for block `N` can never be reclaimed. [4](#0-3) 

---

### Likelihood Explanation

**High.** The attack requires no special role, no leaked key, no token approval, and no capital. Any Starknet account can submit this transaction. The attacker can automate it to fire every block, continuously suppressing all consensus rewards at negligible cost (only gas). There is no economic barrier.

---

### Recommendation

Restrict who may call `update_rewards`. The function is intended to be called by the attestation contract (pre-consensus) or by a staker/operator on their own behalf (consensus). Add an access-control check, for example:

```cairo
assert!(
    get_caller_address() == staker_address
        || get_caller_address() == self.attestation_contract.read(),
    "{}",
    Error::UNAUTHORIZED_CALLER,
);
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and derive the flag internally from protocol state, so no external caller can influence whether rewards are distributed.

---

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and the current epoch has passed it).
2. At block `N`, before any staker calls `update_rewards`, attacker `Eve` submits:
   ```
   staking.update_rewards(staker_address=any_valid_staker, disable_rewards=true)
   ```
3. Inside the call:
   - `current_block_number (N) > last_reward_block` → passes.
   - `last_reward_block` is written to `N`.
   - `disable_rewards == true` → function returns immediately, no rewards distributed.
4. Any legitimate staker or operator now calls `update_rewards(staker, false)` in block `N`:
   - `current_block_number (N) > last_reward_block (N)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
5. Block `N` rewards are permanently lost for all stakers.
6. Eve repeats this every block at negligible cost, continuously suppressing all consensus block rewards. [5](#0-4) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1508)
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
