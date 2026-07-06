### Title
Any Caller Can Suppress Consensus Block Rewards by Calling `update_rewards` with `disable_rewards=true` — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract writes to the global `last_reward_block` storage variable **before** checking the `disable_rewards` flag. Because the function has no access control beyond a non-zero caller check, any unprivileged address can call it with `disable_rewards=true` to advance `last_reward_block` without distributing any rewards, permanently blocking legitimate reward distribution for that block.

---

### Finding Description

`StakingRewardsManagerImpl::update_rewards` is a publicly callable function (embedded via `#[abi(embed_v0)]`) that only enforces `general_prerequisites()` — a check for contract pause state and a non-zero caller. No role-based access control exists.

The execution order inside the function is:

1. **Line 1454–1458**: Guard — asserts `current_block_number > self.last_reward_block.read()`. If false, reverts with `REWARDS_ALREADY_UPDATED`.
2. **Lines 1460–1482**: Validates that `staker_address` exists, is active, and has non-zero balance.
3. **Line 1485**: `self.last_reward_block.write(current_block_number)` — **global state is mutated here, unconditionally**.
4. **Lines 1487–1489**: `if disable_rewards || self.is_pre_consensus() { return; }` — early return with no rewards distributed.
5. **Lines 1492–1506**: Actual reward calculation and distribution (only reached if `disable_rewards == false` and consensus is active).

The critical flaw is that `last_reward_block` is advanced at step 3 regardless of the `disable_rewards` flag. Because the guard at step 1 uses `last_reward_block` as a per-block mutex, any caller who reaches step 3 first — even with `disable_rewards=true` — consumes the block's reward slot without distributing anything.

This is structurally identical to the reported vulnerability: a shared global counter is updated before the check that would have prevented the update, allowing an unprivileged actor to exhaust the shared resource and deny service to legitimate participants.

---

### Impact Explanation

An attacker calling `update_rewards(valid_staker_address, disable_rewards=true)` at the start of every block:

- Advances `last_reward_block` to the current block number.
- Distributes zero rewards.
- Causes every subsequent legitimate call to `update_rewards` in that block to revert with `REWARDS_ALREADY_UPDATED`.
- Permanently destroys the block rewards for all stakers for that block.

Repeated every block, this **permanently freezes all consensus-phase block rewards** for every staker and delegator in the protocol. The lost rewards are never recoverable — they are simply never minted/claimed. This matches the **High** impact category: *Permanent freezing of unclaimed yield*.

---

### Likelihood Explanation

The attack requires:
- No capital (only gas fees).
- No privileged role or leaked key.
- Only a valid (non-zero) staker address, which is publicly observable on-chain.

The attacker can automate the call at the start of each block. The cost is purely gas; the damage scales to the entire staker population. Likelihood is **High**.

---

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` early-return check, so the global state is only advanced when rewards are actually distributed:

```cairo
// Update last block rewards ONLY when rewards will be distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number); // moved here
// ... reward calculation and distribution ...
```

Alternatively, add role-based access control to `update_rewards` so only the authorized consensus caller can invoke it.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker observes any valid, active staker address `S` on-chain.
3. At block `N`, attacker calls `Staking::update_rewards(S, disable_rewards=true)`.
4. Inside the function: `current_block_number (N) > last_reward_block` → passes. Staker validation passes. `last_reward_block` is written to `N`. Function returns early — **no rewards distributed**.
5. Legitimate validator/staker calls `update_rewards(S, disable_rewards=false)` in the same block `N`. The guard `N > N` is `false` → reverts with `REWARDS_ALREADY_UPDATED`.
6. Block `N` rewards are permanently lost.
7. Attacker repeats at block `N+1`, `N+2`, … to freeze all future consensus rewards.

---

**Root cause location:** [1](#0-0) 

The global write at line 1485 precedes the `disable_rewards` guard at line 1487, and the function carries no access control beyond `general_prerequisites()` at line 1452. [2](#0-1)

### Citations

**File:** src/staking/staking.cairo (L1448-1489)
```text
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
