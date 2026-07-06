### Title
Unrestricted `disable_rewards` Flag in `update_rewards` Allows Any Caller to Permanently Suppress Block Reward Distribution — (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is a public, permissionless function that accepts a caller-controlled `disable_rewards: bool` parameter. Because there is no access-control check, any unprivileged address can call `update_rewards(staker_address, disable_rewards: true)` for any staker at any block, consuming the single global `last_reward_block` slot for that block and permanently suppressing reward distribution for every staker in that block.

---

### Finding Description

`update_rewards` in `src/staking/staking.cairo` is the consensus-rewards entry point (V3). Its first action is to assert the current block has not already been processed, then unconditionally write `last_reward_block = current_block_number`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // consumed for this block

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits without distributing rewards
    }
    ...
``` [1](#0-0) 

`last_reward_block` is a **single global field** (not per-staker): [2](#0-1) 

`general_prerequisites()` only enforces "not paused" and "caller is not zero address" — no role or identity check: [3](#0-2) 

Contrast this with `update_rewards_from_attestation_contract`, which correctly restricts its caller: [4](#0-3) 

Because `last_reward_block` is global, a single call to `update_rewards(any_staker, disable_rewards: true)` at block N marks block N as "already processed" for **all** stakers. Any subsequent legitimate call at the same block reverts with `REWARDS_ALREADY_UPDATED`, and the block's rewards are permanently unrecoverable.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker calling `update_rewards(any_staker, disable_rewards: true)` once per block (or front-running legitimate calls) causes every staker's block rewards to be silently skipped. Because `last_reward_block` is consumed and never rolled back, the yield for each skipped block is permanently lost — it cannot be reclaimed in a later block. Over time this drains all staker and delegator yield.

---

### Likelihood Explanation

The attack requires only a valid (non-zero) Starknet address and enough gas to submit one transaction per block. No privileged role, leaked key, or external dependency is needed. A motivated attacker (e.g., a competing validator or someone shorting STRK) has clear economic incentive. Front-running is straightforward on Starknet because transaction ordering is observable.

---

### Recommendation

Restrict who may supply `disable_rewards: true`. Two options:

1. **Preferred**: Remove the `disable_rewards` parameter from the public interface entirely. Let the contract derive whether rewards should be disabled from on-chain attestation records (analogous to how `update_rewards_from_attestation_contract` is gated to the attestation contract).
2. **Minimal fix**: Add an access-control assertion so only the attestation contract (or another trusted role) may call `update_rewards` with `disable_rewards: true`; any other caller must pass `false`, or the function should be split into two entry points with separate access controls.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker `A` (any non-zero address) monitors the chain.
3. At every new block `N`, `A` calls:
   ```
   staking.update_rewards(staker_address: any_valid_staker, disable_rewards: true)
   ```
4. The contract writes `last_reward_block = N` and returns without distributing rewards.
5. Any legitimate call to `update_rewards(..., disable_rewards: false)` at block `N` reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers and their delegators receive zero block rewards for block `N`; the yield is permanently lost.
7. Repeating step 3 every block permanently freezes all consensus-era yield across the entire protocol.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
