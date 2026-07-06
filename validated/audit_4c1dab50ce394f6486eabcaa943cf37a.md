Looking at the `update_rewards` function in `src/staking/staking.cairo` and the global `last_reward_block` state variable, I can identify a clear analog to the governance hostage-taking vulnerability.

### Title
Any Caller Can Permanently Freeze Consensus Reward Distribution via `update_rewards` with `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary
`update_rewards` is a publicly callable function with no access control. It writes to the global `last_reward_block` storage variable **before** checking the `disable_rewards` flag. Any unprivileged caller can invoke `update_rewards(staker_address: any_valid_staker, disable_rewards: true)` once per block to consume the block's reward slot without distributing any rewards, permanently freezing consensus yield for all stakers and delegators.

### Finding Description

`update_rewards` in `IStakingRewardsManager` is exposed as a public ABI function with no caller restriction. Its logic is:

1. Assert `current_block_number > last_reward_block` (global, per-block gate)
2. Validate that `staker_address` is an active staker with non-zero balance
3. **Write** `last_reward_block = current_block_number` — consuming the slot
4. If `disable_rewards == true` **or** pre-consensus: **return early** without distributing rewards [1](#0-0) 

The `last_reward_block` is a **global** (not per-staker) storage variable. Once it is written to the current block number, no other call to `update_rewards` can succeed in the same block. [2](#0-1) 

The `disable_rewards` parameter is part of the public interface `IStakingRewardsManager` with no documentation restricting who may pass `true`: [3](#0-2) 

An attacker who knows any valid, active staker address (trivially discoverable from on-chain events) can call `update_rewards(staker_address: victim_staker, disable_rewards: true)` in every block. Each call:
- Passes all validation (staker is valid and active)
- Writes `last_reward_block` to the current block
- Returns without distributing any rewards

This is directly analogous to the Olympus governance attack: just as an attacker with 20% voting power could repeatedly activate a dummy proposal to block all other proposals for a `GRACE_PERIOD`, here an attacker with **zero stake** can repeatedly call `update_rewards(..., disable_rewards: true)` to block all reward distribution for every block indefinitely.

### Impact Explanation

In the consensus rewards phase, `update_rewards` is the sole mechanism by which block-level STRK and BTC rewards are credited to stakers and their delegation pools. By consuming the per-block slot with `disable_rewards: true`, the attacker causes every block's rewards to be silently skipped. Stakers and delegators accumulate zero yield for as long as the attack continues. This constitutes **permanent freezing of unclaimed yield** for all protocol participants. [4](#0-3) 

### Likelihood Explanation

- **No stake required**: The attacker needs only gas to call the function once per block.
- **No privileged access**: The function has no `only_*` role guard.
- **Trivially repeatable**: The attacker simply submits one transaction per block. On Starknet, block times are short, making this a low-cost sustained attack.
- **Front-running**: Even if a legitimate caller attempts `update_rewards(..., disable_rewards: false)`, the attacker can front-run with `disable_rewards: true` in the same block.
- **Valid staker address**: Any staker address is observable from `NewStaker` events emitted on-chain.

### Recommendation

1. **Restrict `disable_rewards: true` to privileged callers only** (e.g., `only_app_governor` or `only_security_agent`), or remove the `disable_rewards` parameter from the public interface entirely.
2. Alternatively, **move the `last_reward_block` write to after the `disable_rewards` check**, so that a no-op call does not consume the block's reward slot.
3. Consider adding an explicit caller whitelist (e.g., only the staker themselves or their operational address may call `update_rewards` for their own `staker_address`).

### Proof of Concept

```
// Attacker (any EOA, zero stake) calls once per block:
staking_contract.update_rewards(
    staker_address: any_valid_active_staker,  // observable from NewStaker events
    disable_rewards: true,
);
// Result:
//   last_reward_block = current_block  (slot consumed)
//   No rewards distributed
//   Any subsequent update_rewards call in this block reverts with REWARDS_ALREADY_UPDATED
// Repeat every block → all consensus rewards permanently frozen
``` [5](#0-4) [2](#0-1)

### Citations

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

**File:** src/staking/staking.cairo (L1491-1507)
```text
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

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
