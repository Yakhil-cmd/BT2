### Title
Missing Caller Validation in `update_rewards` Allows Any Address to Suppress Block Reward Distribution - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract validates the supplied `staker_address` but performs **no validation on `get_caller_address()`**. Because the function also accepts a caller-controlled `disable_rewards: bool` parameter and unconditionally writes the global `last_reward_block` before checking that flag, any unprivileged address can call `update_rewards(any_valid_staker, true)` to consume the per-block reward slot without distributing any rewards — permanently denying all stakers their consensus block rewards for that block.

---

### Finding Description

`update_rewards` is part of the `IStakingRewardsManager` interface and is callable by any non-zero address (enforced only by `general_prerequisites()`). [1](#0-0) 

The function validates that `staker_address` is a registered, active staker with non-zero balance: [2](#0-1) 

It then **unconditionally** writes the current block number to the global `last_reward_block` storage slot: [3](#0-2) 

Only *after* that write does it check `disable_rewards`: [4](#0-3) 

`last_reward_block` is a **single global value** shared across all stakers: [5](#0-4) 

The guard at the top of the function prevents any second call in the same block: [6](#0-5) 

**Consequence**: An attacker who calls `update_rewards(any_valid_staker, true)` first in a block:
1. Passes all staker-validity checks (using any legitimate staker address).
2. Advances `last_reward_block` to the current block.
3. Returns immediately without distributing rewards (`disable_rewards = true`).
4. Causes every subsequent `update_rewards` call in that block to revert with `REWARDS_ALREADY_UPDATED`.

No staker receives block rewards for that block. The attacker repeats this every block to sustain the denial.

This is structurally identical to the USDKG analog: `transferFrom` validated `_from` but not `msg.sender`; here `update_rewards` validates `staker_address` but not `get_caller_address()`.

---

### Impact Explanation

**Medium — Griefing with no profit motive but damage to users or protocol.**

All stakers are denied consensus block rewards for every block the attacker front-runs. The staking contract's `last_reward_block` is consumed without any reward being credited to `unclaimed_rewards_own` or forwarded to delegation pools. Rewards for skipped blocks are permanently lost (the per-block reward calculation is not retroactive).

---

### Likelihood Explanation

**Medium.** Any address can call `update_rewards`. On Starknet, transaction ordering within a block is deterministic and sequencer-controlled, so a well-resourced attacker (or a griefing sequencer) can reliably place their call before the legitimate one. The only cost is gas per block. No privileged access, leaked key, or external dependency is required.

---

### Recommendation

Add a caller-authorization check at the top of `update_rewards`. Only the staker themselves, their registered `operational_address`, or an explicitly whitelisted keeper contract should be permitted to call this function. For example:

```cairo
let caller = get_caller_address();
assert!(
    caller == staker_address
        || caller == staker_info.operational_address
        || self.is_authorized_keeper(caller),
    "{}",
    Error::UNAUTHORIZED_CALLER,
);
```

Alternatively, remove the `disable_rewards` parameter from the public interface and handle that logic internally (e.g., detect the unstake-intent state automatically), so there is no caller-controlled knob that can suppress reward distribution.

---

### Proof of Concept

1. Staker `S` is registered and active with non-zero STRK balance.
2. At block `N`, the legitimate keeper (or `S` themselves) intends to call `update_rewards(S, false)` to credit block rewards.
3. Attacker `A` (any EOA) calls `update_rewards(S, true)` in the same block, earlier in the transaction ordering.
4. `last_reward_block` is set to `N`; no rewards are distributed.
5. The legitimate call arrives and reverts: `current_block_number > self.last_reward_block.read()` is `false`.
6. Block `N` rewards are permanently lost for all stakers.
7. Attacker repeats step 3 every block to sustain the attack indefinitely.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1452)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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

**File:** src/staking/staking.cairo (L1484-1485)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);
```

**File:** src/staking/staking.cairo (L1487-1489)
```text
            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
