### Title
Unprivileged Caller Can Permanently Freeze Staker Yield by Consuming the Per-Block Reward Slot via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

---

### Summary

Any non-zero address can call the public `update_rewards` function with `disable_rewards: true` for any valid staker. Because `last_reward_block` is written to storage **before** the `disable_rewards` guard, the global per-block reward slot is consumed without distributing any rewards. A persistent attacker can repeat this every block, permanently preventing all stakers from accumulating yield.

---

### Finding Description

`update_rewards` is part of the public `IStakingRewardsManager` interface. Its only access gate is `general_prerequisites`, which checks that the contract is not paused and the caller is non-zero. [1](#0-0) 

The function enforces a global, single-staker-per-block invariant via `last_reward_block`: [2](#0-1) 

Critically, `last_reward_block` is written to storage **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

This means any caller can invoke `update_rewards(any_active_staker, disable_rewards: true)`, atomically:
1. Advance `last_reward_block` to the current block number.
2. Return immediately without distributing any rewards.

Any subsequent call to `update_rewards` in the same block — including the legitimate call from the attesting staker — will revert with `REWARDS_ALREADY_UPDATED`.

The `general_prerequisites` check that gates the function: [4](#0-3) 

imposes no restriction on who may call `update_rewards` or what value they pass for `disable_rewards`.

---

### Impact Explanation

Each Starknet block, exactly one staker is entitled to consensus rewards. If an attacker calls `update_rewards(victim, disable_rewards: true)` before the victim's legitimate call, the victim's reward for that block is permanently lost — it is never credited to `unclaimed_rewards_own` and never claimed from the reward supplier. Repeating this every block causes **permanent freezing of unclaimed yield** for all stakers. Even sporadic execution constitutes griefing with measurable damage to staker yield.

This matches the allowed impact: **Permanent freezing of unclaimed yield** (High) / **Griefing with no profit motive but damage to users or protocol** (Medium).

---

### Likelihood Explanation

- The entry point is fully public; no role, key, or privileged access is required.
- The attacker only needs to be a non-zero address and supply any currently-active staker address.
- The active staker set is publicly enumerable via `get_stakers`.
- On Starknet, transaction ordering is controlled by the sequencer; an attacker can submit the griefing transaction in the same block as the victim's attestation.
- Gas cost per block is the only barrier; there is no on-chain defense.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` guard, so that consuming the slot only occurs when rewards are actually distributed:

```cairo
// Update last block rewards ONLY when rewards will be distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
// ... reward distribution logic ...
```

Alternatively, restrict who may pass `disable_rewards: true` (e.g., only the staker themselves or a designated operator role).

---

### Proof of Concept

1. Staker `S` attests in block `B` and prepares to call `update_rewards(S, false)`.
2. Attacker `A` (any non-zero address) calls `update_rewards(S, true)` in the same block `B`.
3. `last_reward_block` is set to `B`; no rewards are distributed.
4. Staker `S`'s call reverts: `current_block_number > self.last_reward_block.read()` is false.
5. Staker `S` permanently loses the block reward for block `B`.
6. Repeating step 2 every block causes `S` (and all other stakers) to never accumulate yield. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1448-1460)
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
```

**File:** src/staking/staking.cairo (L1484-1507)
```text
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
