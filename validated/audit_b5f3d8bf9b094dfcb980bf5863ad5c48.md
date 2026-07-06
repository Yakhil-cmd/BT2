### Title
Unprivileged caller can permanently freeze all staker block rewards by front-running `update_rewards` with `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract has no caller authorization. Any non-zero address can call it with `disable_rewards: true`, which advances the global `last_reward_block` to the current block without distributing any rewards. Because the one-call-per-block guard is keyed on this global, the legitimate consensus call for that block is permanently blocked, and the block's rewards are never credited to any staker.

### Finding Description
`update_rewards` is part of `StakingRewardsManagerImpl` and is the sole entry point for per-block consensus reward distribution. Its access guard is only `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address. [1](#0-0) 

The function then unconditionally writes `current_block_number` to `last_reward_block` **before** inspecting `disable_rewards`: [2](#0-1) 

After that write, if `disable_rewards` is `true` (or the contract is pre-consensus), the function returns immediately without calling `_update_rewards`: [3](#0-2) 

Because `last_reward_block` is now equal to `current_block_number`, any subsequent call to `update_rewards` in the same block will fail the assertion:

```
assert!(current_block_number > self.last_reward_block.read(), ...)
```

The rewards that should have been credited for that block are never computed and never added to any staker's `unclaimed_rewards_own`. They are permanently lost.

An attacker repeats this at the first transaction of every block, using any known active staker address (all staker addresses are public on-chain). The cost is one cheap transaction per block; the profit motive is irrelevant — the damage is protocol-wide.

### Impact Explanation
Every block whose `update_rewards` slot is consumed by the attacker's `disable_rewards: true` call produces zero rewards for all stakers and all pool members. Because the per-block reward is never accumulated, it cannot be recovered by any later `claim_rewards` call. This constitutes **permanent freezing of unclaimed yield** for the entire staker set, matching the High-severity impact category.

### Likelihood Explanation
- No privileged role is required; any EOA or contract with a non-zero address suffices.
- The only prerequisite is knowing one active staker address, which is trivially obtained from on-chain events (`NewStaker`).
- The attacker pays one transaction per block (~3 s on Starknet). Gas cost is low relative to the protocol-wide yield destroyed.
- No coordination or special timing beyond "be first in the block" is needed.

### Recommendation
Restrict `update_rewards` to an authorized caller (e.g., the attestation contract or a designated consensus sequencer role), mirroring the pattern already used in `update_rewards_from_attestation_contract`: [4](#0-3) 

Alternatively, remove the `disable_rewards` parameter entirely and derive the skip-rewards decision internally (e.g., from `is_pre_consensus()` or a staker-removal flag), so no external caller can suppress reward distribution.

### Proof of Concept
```
// Attacker script — runs once per block
loop {
    wait_for_new_block();
    // any_active_staker is read from on-chain NewStaker events
    staking_contract.update_rewards(any_active_staker, disable_rewards: true);
    // last_reward_block is now == current block
    // legitimate consensus call will revert with REWARDS_ALREADY_UPDATED
    // block rewards are permanently lost for all stakers
}
```

Step-by-step:
1. Block N begins. Attacker calls `update_rewards(valid_staker, true)`.
2. `general_prerequisites()` passes (not paused, caller ≠ 0). [5](#0-4) 
3. `current_block_number (N) > last_reward_block` — assertion passes.
4. `last_reward_block` is written to `N`. [6](#0-5) 
5. `disable_rewards == true` → function returns; `_update_rewards` is never called.
6. Any legitimate call to `update_rewards` for block N now reverts (`N > N` is false).
7. Block N's rewards are permanently unaccounted for every staker.
8. Attacker repeats at block N+1, N+2, …

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

**File:** src/staking/staking.cairo (L1449-1456)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
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
