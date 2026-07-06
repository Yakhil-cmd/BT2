### Title
Unrestricted `update_rewards` with `disable_rewards=true` Permanently Freezes Block Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the staking contract is callable by any unprivileged address. Because `last_reward_block` is written **before** the `disable_rewards` guard, an attacker can call `update_rewards(any_valid_staker, disable_rewards=true)` once per block to consume the block's reward slot without distributing any rewards, permanently destroying that block's unclaimed yield.

### Finding Description
`update_rewards` is exposed as a fully public entrypoint under `IStakingRewardsManager`. Its only gate is `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero — no role or identity check is performed.

The critical ordering inside the function is:

```
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← slot consumed here

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← rewards silently dropped
}
``` [1](#0-0) 

`last_reward_block` is a single global counter that enforces at most one reward distribution per block: [2](#0-1) 

Because the write to `last_reward_block` happens unconditionally before the `disable_rewards` branch, any caller can:

1. Supply any currently-active `staker_address` (trivially satisfied by reading on-chain state).
2. Pass `disable_rewards = true`.
3. The slot is consumed; no STRK is distributed to any staker or pool for that block.

The `general_prerequisites` function that guards every public entry point only checks pause state and non-zero caller: [3](#0-2) 

There is no check that the caller is the staker, the operational address, the attestation contract, or any other privileged role.

### Impact Explanation
Each Starknet block carries a discrete STRK (and BTC) reward computed by `calculate_block_rewards`. If `update_rewards` is called with `disable_rewards=true`, those rewards are never minted/transferred to anyone — they are permanently lost. An attacker who calls this function once per block (cheap on Starknet) causes **permanent, irreversible destruction of all consensus-era block rewards** for every staker and every delegation pool. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation
- The function is fully public with no role restriction.
- The attacker needs only a valid (active) staker address, which is trivially readable from on-chain events or `get_stakers`.
- Gas cost per block on Starknet is negligible.
- No profit motive is required; a competitor, a disgruntled actor, or an automated bot can sustain the attack indefinitely.

### Recommendation
Restrict `update_rewards` to a trusted caller. The most natural choice is to allow only the staker's own operational address (already stored in `staker_info.operational_address`) or a designated sequencer/rewards-manager role. At minimum, the `disable_rewards=true` path must require a privileged caller, and `last_reward_block` must only be written when rewards are actually going to be distributed (or the write must be gated on the same condition).

### Proof of Concept

```
// Attacker script — run once per block
loop {
    let valid_staker = staking.get_stakers(current_epoch)[0].staker_address;
    staking.update_rewards(
        staker_address: valid_staker,
        disable_rewards: true,   // ← no access control prevents this
    );
    // last_reward_block is now == current_block_number
    // No STRK distributed; rewards permanently lost for this block
    wait_for_next_block();
}
```

1. Attacker reads any active staker address from `get_stakers` or past `NewStaker` events.
2. Calls `update_rewards(staker, true)` — passes all checks in `general_prerequisites` and the staker-validity assertions.
3. `last_reward_block` is set to the current block number at line 1485.
4. The `if disable_rewards` branch fires at line 1487, returning before `_update_rewards` is ever reached.
5. Any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. The block's STRK and BTC rewards are permanently unclaimable. [4](#0-3)

### Citations

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
