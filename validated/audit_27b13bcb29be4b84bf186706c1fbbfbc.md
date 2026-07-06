### Title
Attacker Can Permanently Freeze Block Rewards by Calling `update_rewards` with `disable_rewards: true` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable by any non-zero address. It writes to the global `last_reward_block` variable **before** checking the `disable_rewards` flag. An attacker can call `update_rewards(valid_staker, disable_rewards: true)` at the start of any block to consume the single allowed reward-update slot for that block, permanently preventing legitimate block reward distribution — at essentially zero cost.

---

### Finding Description

`update_rewards` is exposed as a public ABI function via `IStakingRewardsManager` with no access control beyond `general_prerequisites()`, which only checks that the contract is unpaused and the caller is non-zero. [1](#0-0) 

The execution path is:

1. Assert `current_block_number > last_reward_block` (one call per block, globally).
2. Validate the staker exists and is active with non-zero balance.
3. **Write `last_reward_block = current_block_number`** — this happens unconditionally.
4. If `disable_rewards || is_pre_consensus()` → return early, distributing **no rewards**. [2](#0-1) 

Because `last_reward_block` is a **global** storage variable (not per-staker), a single call with any valid staker address and `disable_rewards: true` consumes the entire block's reward slot. Any subsequent legitimate call for that block fails with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

The `general_prerequisites` function imposes no role check: [4](#0-3) 

---

### Impact Explanation

Block rewards for the targeted block are **permanently lost** — they are never distributed to stakers or pools. The attacker can repeat this every block to permanently freeze all consensus reward distribution across the entire protocol. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- Valid staker addresses are publicly discoverable from `NewStaker` events.
- The attacker only needs to submit a transaction calling `update_rewards(valid_staker, true)` before the legitimate block-proposer call in each block.
- The attacker loses **nothing** — no funds are transferred, only gas is spent (negligible on Starknet).
- The attack is fully automatable and can be sustained indefinitely.

---

### Recommendation

Two mitigations are possible:

1. **Access control**: Restrict `update_rewards` so only an authorized caller (e.g., the block proposer's registered operational address, or a dedicated consensus contract) can invoke it.
2. **Reorder the write**: Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` check, so a call with `disable_rewards: true` does not consume the block's reward slot. [5](#0-4) 

---

### Proof of Concept

1. Attacker identifies any valid, active staker address `S` with non-zero balance (from on-chain events).
2. At the start of block `N`, attacker submits: `staking.update_rewards(S, disable_rewards: true)`.
3. The call passes all checks, writes `last_reward_block = N`, then returns early — **no rewards distributed**.
4. The legitimate block-proposer's call `staking.update_rewards(proposer, disable_rewards: false)` reverts with `REWARDS_ALREADY_UPDATED` because `current_block_number == last_reward_block`.
5. Block `N`'s rewards are permanently lost.
6. Attacker repeats every block, permanently halting all consensus reward distribution at the cost of gas only. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1187-1188)
```text
            let to_staker_info = self.internal_staker_info(staker_address: to_staker);

```

**File:** src/staking/staking.cairo (L1448-1507)
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
