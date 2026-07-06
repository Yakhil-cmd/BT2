### Title
Unprivileged Caller Can Permanently Suppress Per-Block Consensus Rewards for All Stakers via `disable_rewards` Flag in `update_rewards` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable with no access control. It accepts a `disable_rewards: bool` parameter and unconditionally writes the current block number to the global `last_reward_block` storage variable **before** checking the flag. Any unprivileged caller can invoke `update_rewards(any_active_staker, disable_rewards: true)` once per block to permanently skip consensus reward distribution for that block for every staker in the protocol, because the one-call-per-block invariant is consumed without distributing any rewards.

---

### Finding Description

`update_rewards` is part of `IStakingRewardsManager` and is embedded in the public ABI via `#[abi(embed_v0)]`. Its only gate is `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address — no role or identity check is performed.

The critical ordering inside the function is:

```
// 1. Enforce one-call-per-block globally
assert!(current_block_number > self.last_reward_block.read(), REWARDS_ALREADY_UPDATED);

// 2. Validate staker exists and is active (uses any valid staker_address)
...

// 3. Consume the block slot — written BEFORE the disable_rewards branch
self.last_reward_block.write(current_block_number);   // ← slot consumed here

// 4. Early-return without distributing rewards
if disable_rewards || self.is_pre_consensus() {
    return;
}
// 5. Actual reward calculation and distribution (never reached if step 4 returns)
```

`last_reward_block` is a **single global** storage variable shared across all stakers. Once it is written to block N, every subsequent call to `update_rewards` in block N reverts with `REWARDS_ALREADY_UPDATED`. Because the write happens unconditionally before the `disable_rewards` branch, an attacker who calls `update_rewards(any_active_staker, true)` in block N permanently forfeits the consensus reward distribution for **all** stakers for that block. There is no recovery path.

The attacker only needs to supply any currently-active staker address (publicly readable from the `stakers` vector) and pay the gas cost of one transaction per block.

---

### Impact Explanation

This is a **Medium** impact: griefing with no direct profit motive but concrete, permanent damage to users and the protocol.

- Every block in which the attacker front-runs the legitimate `update_rewards` call results in zero consensus rewards distributed to any staker.
- Rewards are not deferred or queued; the missed block's rewards are simply never credited to `unclaimed_rewards_own` or to delegation pools.
- Sustained over many blocks, this constitutes a permanent freezing of unclaimed yield for all stakers and pool members.
- The attacker bears only gas costs; there is no economic barrier preventing continuous execution.

---

### Likelihood Explanation

**Medium-to-High likelihood.**

- The function is unconditionally public; no special role, key, or privileged access is required.
- The attacker only needs to submit one transaction per block with a valid (publicly known) staker address and `disable_rewards: true`.
- On Starknet, transaction ordering within a block is controlled by the sequencer. A motivated attacker (e.g., a competing staker or a protocol adversary) can reliably place this call first in each block.
- The cost is a single low-gas call per block; the economic asymmetry strongly favors the attacker.

---

### Recommendation

1. **Add access control** to `update_rewards`: restrict callers to the consensus mechanism contract, the staker themselves, or a designated operator role. The `disable_rewards` flag is only meaningful when called by the entity that knows whether a staker produced a block.
2. **Reorder the write**: move `self.last_reward_block.write(current_block_number)` to after the `disable_rewards` branch so that a no-op call does not consume the block slot.
3. **Consider per-staker tracking** of `last_reward_block` if independent per-staker reward updates are required, to avoid the global slot being consumed by a call targeting an arbitrary staker.

---

### Proof of Concept

1. The protocol is in post-consensus mode (`consensus_rewards_first_epoch` has been set and the current epoch is ≥ that value).
2. Stakers A, B, C are all active with non-zero balances.
3. In block N, the attacker calls:
   ```
   staking.update_rewards(staker_A_address, disable_rewards: true)
   ```
4. Inside the function:
   - `current_block_number (N) > last_reward_block` → assertion passes.
   - Staker A is validated as active.
   - `last_reward_block` is written to N.
   - `disable_rewards == true` → early return; no rewards distributed.
5. Any subsequent call to `update_rewards` in block N (for staker A, B, or C) reverts with `REWARDS_ALREADY_UPDATED`.
6. Stakers A, B, and C receive zero consensus rewards for block N.
7. The attacker repeats this every block, permanently suppressing all consensus reward accrual across the protocol.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1186-1199)
```text

            let to_staker_info = self.internal_staker_info(staker_address: to_staker);

            // More asserts.
            assert!(to_staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            let to_token_address = self
                .staker_pool_info
                .entry(to_staker)
                .get_pool_token(pool_contract: to_pool)
                .expect_with_err(Error::DELEGATION_POOL_MISMATCH);
            assert!(token_address == to_token_address, "{}", Error::TOKEN_MISMATCH);

            // Update `to_staker`'s delegated stake amount, and add to total stake.
            let old_delegated_stake = self
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
