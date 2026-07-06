### Title
Unpermissioned `update_rewards` with `disable_rewards: true` Allows Any Caller to Permanently Freeze Consensus Yield for All Stakers - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` is a public, permissionless function that accepts a caller-controlled `disable_rewards` flag. Because the global `last_reward_block` is written unconditionally before the rewards-distribution branch, any unprivileged caller can invoke `update_rewards(any_valid_staker, disable_rewards: true)` once per block to consume the per-block reward slot without distributing any yield. Repeated across every block, this permanently freezes all consensus-era staker and delegator rewards at zero cost beyond gas.

### Finding Description

`update_rewards` in `src/staking/staking.cairo` is exposed as a public ABI entry point with no role check beyond `general_prerequisites()` (which only asserts the contract is unpaused and the caller is non-zero). [1](#0-0) 

The critical sequence inside the function is:

1. Assert `current_block_number > last_reward_block` — ensures only one call per block succeeds.
2. **Write `last_reward_block = current_block_number` unconditionally** — this happens before the rewards branch.
3. If `disable_rewards == true` **or** `is_pre_consensus()`, return immediately without distributing any rewards. [2](#0-1) 

`last_reward_block` is a single global `BlockNumber` field, not a per-staker map: [3](#0-2) 

Because the slot is consumed globally, a single call with `disable_rewards: true` in block N prevents every other staker from calling `update_rewards` in block N (they all revert with `REWARDS_ALREADY_UPDATED`). [4](#0-3) 

The only prerequisite is that the supplied `staker_address` is an active staker with non-zero balance — a condition trivially satisfied by reading any live staker from on-chain events.

### Impact Explanation

An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` at the start of every block:

- Consumes the single per-block reward slot for the entire protocol.
- Causes `last_reward_block` to advance each block with zero rewards distributed.
- Permanently freezes all consensus-era staker own-rewards (`unclaimed_rewards_own`) and all delegation-pool rewards (`update_rewards_from_staking_contract` is never reached).

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- No special role or privilege is required; any EOA or contract can call `update_rewards`.
- The attacker needs only one transaction per block (cheap on Starknet).
- The attack is fully deterministic and requires no front-running skill — the attacker simply submits first in each block.
- The attack is sustainable indefinitely and is invisible until stakers notice their `unclaimed_rewards_own` never grows.

### Recommendation

Restrict `update_rewards` to a trusted caller (e.g., the consensus/sequencer layer, or the attestation contract), mirroring the pattern already used for `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.assert_caller_is_consensus_contract(); // add this guard
    ...
}
```

Alternatively, move the `last_reward_block.write` to after the rewards-distribution branch so that a `disable_rewards: true` call does not consume the block slot for legitimate callers.

### Proof of Concept

1. Attacker monitors the Starknet mempool / block production.
2. At the start of every block, attacker submits:
   ```
   staking_contract.update_rewards(any_active_staker_address, disable_rewards: true)
   ```
3. `last_reward_block` is set to the current block number with no rewards distributed.
4. Any subsequent call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. After one full epoch of this, all stakers have `unclaimed_rewards_own == 0` and all pool `cumulative_rewards_trace` entries are unchanged — yield is permanently frozen. [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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
