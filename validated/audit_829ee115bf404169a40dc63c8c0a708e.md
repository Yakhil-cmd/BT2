### Title
`last_reward_block` Is Permanently Advanced When `update_rewards` Is Called With `disable_rewards=true` By An Unprivileged Caller — (File: `src/staking/staking.cairo`)

---

### Summary

`StakingRewardsManagerImpl::update_rewards` writes the global `last_reward_block` storage variable **before** checking the `disable_rewards` flag. Because the function has no access control, any unprivileged caller can invoke it with `disable_rewards=true`, permanently consuming the current block's reward slot without distributing any rewards. All subsequent legitimate calls to `update_rewards` in the same block are rejected with `REWARDS_ALREADY_UPDATED`, causing permanent loss of block rewards for every staker.

---

### Finding Description

In `StakingRewardsManagerImpl::update_rewards` the execution order is:

```
1. general_prerequisites()                          // pause + non-zero caller only
2. assert current_block > last_reward_block         // one call per block globally
3. validate staker exists and is active
4. assert staker has non-zero balance
5. last_reward_block.write(current_block_number)    // ← STORAGE MUTATION
6. if disable_rewards || is_pre_consensus() {
       return;                                       // ← EARLY RETURN, no rewards sent
   }
7. _update_rewards(...)                             // actual reward distribution
``` [1](#0-0) 

The global `last_reward_block` field is declared as a single scalar (not a per-staker map): [2](#0-1) 

The write at step 5 is unconditional. The `disable_rewards` branch at step 6 returns without distributing rewards, but `last_reward_block` has already been advanced. Because the guard at step 2 enforces `current_block > last_reward_block`, only **one** call per block is permitted globally. Any call that arrives after the attacker's call in the same block is rejected.

There is no role check anywhere in the function — `general_prerequisites()` only asserts the contract is unpaused and the caller is non-zero: [3](#0-2) 

---

### Impact Explanation

**Permanent freezing of unclaimed yield (High).**

An attacker who calls `update_rewards(any_valid_staker, disable_rewards=true)` in every block:

- Advances `last_reward_block` to the current block without distributing rewards.
- Blocks every legitimate `update_rewards` call for that block with `REWARDS_ALREADY_UPDATED`.
- Causes all stakers to permanently lose their consensus block rewards for every attacked block.

The rewards for each consumed block are irrecoverable — there is no mechanism to retroactively distribute rewards for a block once `last_reward_block` has passed it.

---

### Likelihood Explanation

**High.** The function is publicly callable with no access control. The attack requires one cheap transaction per block. Any address (including a bot) can execute it continuously at negligible cost. The attacker needs no stake, no special role, and no prior setup.

---

### Recommendation

1. **Add access control** to `update_rewards` so only an authorized caller (e.g., the attestation contract or a designated consensus rewards manager) can invoke it.
2. **Alternatively**, move `last_reward_block.write(current_block_number)` to after the `disable_rewards` check, so the block slot is only consumed when rewards are actually distributed.
3. **Remove `disable_rewards` from the public ABI** if it is only intended for internal or privileged use.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. In block N, attacker calls `update_rewards(any_valid_staker_address, disable_rewards: true)`.
3. All validation passes; `last_reward_block` is written to N.
4. The `disable_rewards` branch fires; the function returns with no rewards distributed.
5. The legitimate staker (or anyone else) calls `update_rewards(staker, disable_rewards: false)` in block N — the call reverts with `REWARDS_ALREADY_UPDATED` because `N > N` is false.
6. Block N's rewards are permanently lost.
7. Attacker repeats step 2 in every subsequent block, freezing all consensus block rewards indefinitely.

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
