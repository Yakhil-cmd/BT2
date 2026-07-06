### Title
Unrestricted `update_rewards` with `disable_rewards` Parameter Allows Permanent Freezing of Consensus Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `src/staking/staking.cairo` is callable by any unprivileged address and accepts a caller-controlled `disable_rewards` boolean. When set to `true`, the function updates the global `last_reward_block` without distributing any rewards. Because the global `last_reward_block` lock allows only one successful call per block, an attacker can front-run the legitimate consensus mechanism every block to permanently prevent all stakers from receiving consensus rewards.

### Finding Description
`update_rewards` is implemented in `StakingRewardsManagerImpl` and is exposed as a public entry point with no role check beyond `general_prerequisites` (which only asserts the contract is unpaused and the caller is non-zero). [1](#0-0) 

The function first writes the current block number to the global `last_reward_block`: [2](#0-1) 

It then checks the caller-supplied `disable_rewards` flag: [3](#0-2) 

When `disable_rewards: true`, the function returns immediately after writing `last_reward_block`, distributing nothing. Because the guard at lines 1454-1456 rejects any second call in the same block with `REWARDS_ALREADY_UPDATED`, the attacker's call consumes the entire reward slot for that block.

The missing validation is structurally identical to the referrer-validation class in the external report: just as `buy_ticket` accepted any account as a referrer without verifying the referrer had paid the required fee, `update_rewards` accepts any caller without verifying the caller is the legitimate consensus mechanism. In both cases a prerequisite that should gate the action is simply absent. [4](#0-3) 

`general_prerequisites` contains no role assertion, confirming the entry point is fully open.

### Impact Explanation
An attacker who front-runs `update_rewards` with `disable_rewards: true` every block permanently prevents all stakers from accumulating consensus-phase rewards. Stakers' `unclaimed_rewards_own` fields never increase; delegators' pool sigma values never advance. This constitutes **permanent freezing of unclaimed yield** — a High-severity impact within the allowed scope.

### Likelihood Explanation
The attack requires no privileged key, no token balance, and no prior relationship with any staker. Any EOA or contract can call `update_rewards` with an arbitrary `staker_address` (any currently active staker with non-zero STRK balance) and `disable_rewards: true`. On Starknet, where sequencer ordering is deterministic and mempool visibility is available, consistent front-running is realistic. The attacker's only cost is gas per block.

### Recommendation
Restrict `update_rewards` to a trusted caller (e.g., the attestation contract or a dedicated consensus-rewards caller role), mirroring the pattern already used for `update_rewards_from_attestation_contract`: [5](#0-4) 

Alternatively, remove the `disable_rewards` parameter entirely and derive the "skip rewards" decision internally (e.g., from `is_pre_consensus()` alone), so no external caller can suppress reward distribution.

### Proof of Concept
1. Consensus rewards phase is active (`consensus_rewards_first_epoch` has been set).
2. Attacker identifies any staker `S` that is active and has non-zero STRK balance at the current epoch.
3. In block `N`, attacker submits `update_rewards(S, disable_rewards: true)` with a gas price that ensures it executes before the legitimate consensus call.
4. `last_reward_block` is written to `N`; no rewards are distributed to any staker.
5. The legitimate consensus mechanism's call to `update_rewards(staker_B, disable_rewards: false)` in block `N` reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeating steps 3–5 every block causes all stakers to permanently receive zero consensus rewards, freezing all unclaimed yield indefinitely. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1448-1490)
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

```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
