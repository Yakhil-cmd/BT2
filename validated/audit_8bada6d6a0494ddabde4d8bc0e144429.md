### Title
Unprivileged Caller Can Permanently Freeze All Consensus Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary

`update_rewards` in the Staking contract is callable by any address and accepts a caller-controlled `disable_rewards` boolean. The global `last_reward_block` checkpoint is written **before** the `disable_rewards` guard is evaluated. An unprivileged attacker can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block, consuming the block's single reward slot without distributing any rewards, and blocking every legitimate call in that block with `REWARDS_ALREADY_UPDATED`. Repeated across every block, this permanently freezes all consensus-phase unclaimed yield for all stakers.

### Finding Description

`IStakingRewardsManager::update_rewards` carries no role check — only `general_prerequisites()` (a pause guard). The function enforces a one-call-per-block invariant through the global storage variable `last_reward_block`:

```cairo
// src/staking/staking.cairo  lines ~1452-1488
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // pause check only
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence / balance checks ...

    // ← last_reward_block is committed HERE, before the disable_rewards branch
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits with no rewards paid
    }
    // ... reward calculation and distribution ...
}
```

Because `last_reward_block` is a **single global** variable (not per-staker), one call with any valid `staker_address` and `disable_rewards: true` exhausts the entire block's reward opportunity for every staker. Any subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. [1](#0-0) 

The storage declaration confirms `last_reward_block` is global: [2](#0-1) 

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Consensus rewards are the primary ongoing yield mechanism for all stakers and delegators. By front-running every block's `update_rewards` call with `disable_rewards: true`, an attacker prevents the `_update_rewards` path from ever executing. Stakers accumulate zero consensus rewards indefinitely. Because the attacker only needs to spend gas proportional to block rate (not proportional to the total value locked), the attack is economically viable against a protocol holding significant TVL. The yield is not merely delayed — it is never accrued, so it cannot be claimed later.

### Likelihood Explanation

**High.** The entry point is fully public (no role, no whitelist, no stake requirement). The attacker needs only a valid staker address (readable from on-chain events) and enough gas to submit one transaction per block. No privileged key, bridge access, or external dependency is required.

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` guard, so that a call that skips reward distribution does not consume the block's reward slot:

```cairo
// Update last block rewards only when rewards are actually processed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);  // ← moved here
// ... reward calculation and distribution ...
```

Alternatively, restrict `disable_rewards: true` to a privileged role (e.g., `only_operator`), or remove the parameter entirely if it is not needed by external callers.

### Proof of Concept

1. Deploy the system in consensus-rewards mode (`consensus_rewards_first_epoch` already passed).
2. In every new block, attacker calls:
   ```
   staking.update_rewards(staker_address=<any_active_staker>, disable_rewards=true)
   ```
3. `last_reward_block` is set to the current block; no rewards are distributed.
4. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat each block — all stakers accumulate zero consensus rewards indefinitely.
6. Stakers calling `claim_rewards` receive only previously-accrued amounts; new yield is permanently frozen. [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1490)
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
