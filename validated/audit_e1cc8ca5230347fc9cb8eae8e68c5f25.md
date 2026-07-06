### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Staker Yield - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in `staking.cairo` is specified to be callable only by the Starkware sequencer, but the implementation contains no such access control check. Any unprivileged address can call it with `disable_rewards: true` every block, consuming the global `last_reward_block` slot and permanently preventing the legitimate sequencer from distributing consensus rewards to stakers.

### Finding Description
The protocol specification explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation of `update_rewards` in `StakingRewardsManagerImpl` performs no such check. The only gate is `general_prerequisites()`, which only asserts the contract is unpaused and the caller is non-zero: [2](#0-1) 

The function writes the current block number into the global `last_reward_block` storage variable unconditionally before checking `disable_rewards`: [3](#0-2) 

When `disable_rewards: true` is passed, the function returns immediately after updating `last_reward_block`, without distributing any rewards. The guard at the top of the function then prevents any second call in the same block: [4](#0-3) 

An attacker can call `update_rewards(any_valid_staker_address, disable_rewards: true)` on every block. Because `last_reward_block` is a single global slot (not per-staker), this exhausts the one allowed call per block for the entire contract, and the legitimate sequencer's subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.

### Impact Explanation
This is a **permanent freezing of unclaimed yield**. Stakers and delegators in the consensus rewards phase (`is_pre_consensus() == false`) never accumulate `unclaimed_rewards_own` because `_update_rewards` is never reached. The `RewardSupplier.unclaimed_rewards` is never incremented, and no STRK is ever transferred to stakers or pools. The attack is sustainable at zero cost (only gas) and requires no privileged access.

### Likelihood Explanation
Any address can call `update_rewards` with a valid staker address (staker addresses are public on-chain). The attacker only needs to submit a transaction per block with `disable_rewards: true`. This is a straightforward griefing attack with no barrier to entry once consensus rewards are activated.

### Recommendation
Add a caller restriction to `update_rewards` that asserts `get_caller_address()` equals the configured sequencer/operator address, mirroring the pattern already used in `update_rewards_from_attestation_contract`: [5](#0-4) 

A dedicated `only_sequencer` assertion should be added at the top of `update_rewards`, analogous to `assert_caller_is_attestation_contract`.

### Proof of Concept

1. Consensus rewards are activated (`set_consensus_rewards_first_epoch` has been called and the epoch has passed).
2. A valid staker `S` exists with non-zero balance.
3. Attacker calls `staking.update_rewards(staker_address: S, disable_rewards: true)` at block `N`.
   - `last_reward_block` is written to `N`.
   - Function returns early; no rewards distributed.
4. The legitimate Starkware sequencer calls `staking.update_rewards(staker_address: S, disable_rewards: false)` at block `N`.
   - `current_block_number (N) > last_reward_block (N)` is **false** → reverts with `REWARDS_ALREADY_UPDATED`.
5. Attacker repeats step 3 at every block `N+1, N+2, …`.
6. Stakers and delegators accumulate zero `unclaimed_rewards_own` indefinitely. [6](#0-5)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1447-1507)
```text
    #[abi(embed_v0)]
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

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```
