### Title
Unprivileged Caller Can Permanently Suppress Block Rewards via `update_rewards(disable_rewards: true)` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` has no access control. Any caller can invoke it with `disable_rewards: true` for any valid staker. Because `last_reward_block` is written to storage **before** the `disable_rewards` early-return check, the one-call-per-block slot is consumed without distributing any rewards. Every subsequent legitimate call in the same block reverts with `REWARDS_ALREADY_UPDATED`, permanently forfeiting that block's consensus rewards for all stakers.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero — no role or identity check is performed. [1](#0-0) 

The execution order inside the function is:

1. Assert `current_block_number > last_reward_block` (the per-block gate).
2. Validate the staker exists and is active with non-zero balance.
3. **Write `last_reward_block = current_block_number`** — the slot is consumed here.
4. `if disable_rewards || self.is_pre_consensus() { return; }` — rewards are skipped. [2](#0-1) 

Step 3 commits the block number to storage unconditionally, before the `disable_rewards` branch at step 4. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in a given block:

- Passes all validation checks (only needs a live staker address, which is public on-chain).
- Advances `last_reward_block` to the current block.
- Returns without distributing any STRK or BTC block rewards.

Any honest caller attempting `update_rewards` in the same block then hits: [3](#0-2) 

and reverts. The rewards for that block are permanently lost — there is no mechanism to retroactively distribute skipped block rewards.

`general_prerequisites` provides no caller restriction beyond a zero-address check: [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker running this call every block prevents all stakers from ever accumulating consensus block rewards. The `last_reward_block` storage slot acts as a one-shot fuse per block; once consumed with `disable_rewards: true`, that block's rewards are irrecoverably gone. Over time this drains the entire consensus reward stream for every staker and delegator in the protocol.

---

### Likelihood Explanation

**High.** The attack requires:
- A valid, active staker address (trivially obtained from on-chain `NewStaker` events or `get_stakers()`).
- Gas to submit one transaction per block.
- No privileged role, no leaked key, no external dependency.

The attacker has no profit motive but causes severe, permanent damage to all stakers and delegators.

---

### Recommendation

Restrict `update_rewards` to a trusted caller — either the attestation contract, a designated operator role, or the staking contract itself. For example, add a check analogous to `assert_caller_is_attestation_contract` (already used in `update_rewards_from_attestation_contract`): [5](#0-4) 

Alternatively, move the `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` branch so that a skipped call does not consume the per-block slot.

---

### Proof of Concept

1. Observe any active staker address `S` (e.g., from a `NewStaker` event).
2. At the start of each new block, call:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. The call succeeds: `last_reward_block` is set to the current block, no rewards are distributed.
4. Any honest node or keeper that calls `update_rewards(S, false)` in the same block receives `REWARDS_ALREADY_UPDATED` and reverts.
5. Repeat every block — all consensus block rewards are permanently suppressed across the entire protocol. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
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
