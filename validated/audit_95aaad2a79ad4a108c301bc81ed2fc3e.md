### Title
Unprivileged Caller Can Permanently Freeze All Stakers' Block Rewards via Unvalidated `disable_rewards` Parameter in `update_rewards` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the staking contract is publicly callable by any address and accepts a user-controlled `disable_rewards` boolean. When `true`, reward distribution is skipped for the current block. Critically, the global `last_reward_block` variable is written unconditionally — before the `disable_rewards` check — locking out any legitimate call for the same block. An unprivileged attacker can call `update_rewards(any_valid_staker, true)` every block to permanently freeze consensus block rewards for all stakers.

---

### Finding Description

`update_rewards` is part of `IStakingRewardsManager`, embedded with `#[abi(embed_v0)]`, making it a public ABI entry point with no role restriction. Its execution path is:

1. `self.general_prerequisites()` — only checks the pause flag, no caller check.
2. Assert `current_block_number > self.last_reward_block.read()` — enforces one call per block globally.
3. Validate `staker_address` exists and is active.
4. **`self.last_reward_block.write(current_block_number)`** — global write, unconditional.
5. `if disable_rewards || self.is_pre_consensus() { return; }` — skips reward distribution. [1](#0-0) 

The fatal ordering: `last_reward_block` is committed at step 4, before the `disable_rewards` guard at step 5. Any subsequent call in the same block hits `REWARDS_ALREADY_UPDATED` and reverts.

`last_reward_block` is a single contract-wide storage slot, not per-staker: [2](#0-1) 

Therefore a single call with `disable_rewards = true` blocks reward distribution for **every** staker for that block. Repeating this each block permanently starves all stakers of consensus rewards.

The `general_prerequisites()` call provides no caller restriction — it is the same guard used in fully public functions like `stake()` and `claim_rewards()`: [3](#0-2) [4](#0-3) 

---

### Impact Explanation

An unprivileged attacker calling `update_rewards(valid_staker, true)` at the start of every block permanently prevents all stakers from accruing consensus block rewards. This is **Permanent freezing of unclaimed yield** — a High-severity impact under the allowed scope. The attacker need not be a staker and has no stake at risk.

---

### Likelihood Explanation

High. The function is unconditionally public. Any EOA or contract can call it. Valid staker addresses are enumerable on-chain via the `stakers` vector. Starknet gas costs are low, making per-block calls economically trivial. No special knowledge, privilege, or front-running is required.

---

### Recommendation

Restrict who may supply `disable_rewards = true`. Options:
- Require `get_caller_address() == staker_info.operational_address` (or a designated role) before honouring `disable_rewards = true`.
- Move the `last_reward_block.write` to after the `disable_rewards` guard so that a skipped call does not consume the block's reward slot.
- Remove `disable_rewards` as a caller-supplied parameter entirely and derive the skip condition from internal protocol state only.

---

### Proof of Concept

```
// Attacker script — runs once per block, no stake required
loop every block:
    staking_contract.update_rewards(
        staker_address = <any active staker>,
        disable_rewards = true
    )
```

1. Attacker calls `update_rewards(valid_staker, true)` at block N.
2. `last_reward_block` is written to N; no rewards are distributed.
3. The legitimate operational address attempts `update_rewards(valid_staker, false)` at block N → reverts with `REWARDS_ALREADY_UPDATED`.
4. Repeated every block → all stakers receive zero consensus block rewards indefinitely.

This is the direct analog to the reported starknet-snap issue: just as unvalidated `contractCallData` could be injected by an untrusted caller to corrupt the data displayed in the signing dialog, the unvalidated `disable_rewards` parameter can be injected by any unprivileged caller to corrupt the reward-distribution state of the entire protocol.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L294-296)
```text
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
```

**File:** src/staking/staking.cairo (L1449-1489)
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
```
