### Title
Unrestricted `disable_rewards` Parameter Allows Any Caller to Permanently Freeze Block Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function accepts a caller-controlled `disable_rewards` boolean with no access control. When set to `true`, the function still advances the global `last_reward_block` lock but skips reward distribution entirely. Any unprivileged address can call this every block to permanently consume each block's reward slot without distributing rewards to stakers or pools.

---

### Finding Description

`update_rewards` is the V3 consensus-rewards entry point callable by anyone:

```
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool)
```

The execution order is:

1. Check `current_block_number > last_reward_block` — the global per-block lock [1](#0-0) 
2. Validate the staker exists and is active with non-zero balance [2](#0-1) 
3. **Unconditionally** write `last_reward_block = current_block_number` [3](#0-2) 
4. Return early if `disable_rewards || is_pre_consensus()` — **no rewards distributed** [4](#0-3) 

The only access control is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero: [5](#0-4) 

There is no role check, no restriction on who may set `disable_rewards=true`. Because `last_reward_block` is updated at step 3 before the early-return at step 4, the block's reward slot is consumed regardless of whether rewards are actually distributed.

This is the same accounting-mismatch root cause as the reference report: the accounting state (the block lock) is advanced based on a parameter the attacker controls, while the actual token flow (reward distribution) is skipped — exactly analogous to fees being charged on the input amount while the actual deposit bypasses the fee.

---

### Impact Explanation

An attacker calling `update_rewards(valid_staker, disable_rewards=true)` once per block:

- Permanently consumes that block's reward slot (`last_reward_block` is set and can never be rewound)
- Prevents `_update_rewards` from ever being reached for that block
- `update_unclaimed_rewards_from_staking_contract` is never called on the reward supplier, so no rewards are ever minted or credited
- The yield for that block is permanently lost — it cannot be recovered by any subsequent call

Sustained across every block, this permanently freezes all consensus block rewards for all stakers and delegators. This matches the allowed impact: **Permanent freezing of unclaimed yield (High)**.

---

### Likelihood Explanation

The attack requires:

1. Any valid, active staker address with non-zero STRK balance — trivially found since stakers are stored in the public `stakers` vector [6](#0-5) 
2. One transaction per block with `disable_rewards=true`

Starknet transaction fees are low. The attacker has no profit motive but can sustain the attack indefinitely at minimal cost, permanently denying all stakers their consensus rewards.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` check, so the block slot is only consumed when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only advance the block lock when rewards are actually distributed
self.last_reward_block.write(current_block_number);
// ... calculate and distribute rewards
```

Alternatively, if `disable_rewards` is needed for privileged protocol transitions, gate it behind a role check (e.g., `only_app_governor`) so unprivileged callers cannot set it to `true`.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`)
2. Attacker identifies any valid staker address `S` with non-zero STRK balance from the public `stakers` vector
3. At each new block N, attacker calls `update_rewards(S, disable_rewards=true)`
4. `last_reward_block` is set to N — the block's reward slot is consumed [7](#0-6) 
5. `_update_rewards` is never reached; no rewards are distributed to any staker or pool
6. The yield for block N is permanently lost
7. Repeating this every block permanently freezes all consensus block rewards across the entire protocol

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
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

**File:** src/staking/staking.cairo (L1466-1482)
```text
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
