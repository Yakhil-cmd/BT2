### Title
Missing Caller Identity Verification in `update_rewards` Allows Any Address to Permanently Freeze Per-Block Yield - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract specifies "Only starkware sequencer" as its access control in the protocol spec, but the implementation contains no such check. Any unprivileged address can call `update_rewards` with `disable_rewards: true`, consuming the single global `last_reward_block` slot for the current block and permanently preventing the legitimate sequencer from distributing rewards for that block.

### Finding Description
`IStakingRewardsManager::update_rewards` is the consensus-era reward distribution entry point. The spec at `docs/spec.md:1645` explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation at `src/staking/staking.cairo:1449` only calls `self.general_prerequisites()`, which enforces two checks:

1. Contract is not paused
2. Caller is not the zero address [1](#0-0) 

There is no stored sequencer address and no `assert!(get_caller_address() == sequencer, ...)` guard anywhere in the function. [2](#0-1) 

The critical state variable `last_reward_block` is a **single global** storage slot shared across all stakers: [3](#0-2) 

Once any caller sets it to the current block number, the guard at line 1454–1458 causes every subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`, including the legitimate sequencer's call. [4](#0-3) 

The per-block rewards that were not distributed are permanently lost — `calculate_block_rewards` computes a fixed reward per epoch and there is no carry-forward mechanism for skipped blocks. [5](#0-4) 

### Impact Explanation
An attacker calling `update_rewards(any_active_staker, disable_rewards: true)` in block N:
- Sets `last_reward_block = N`
- Distributes zero rewards (the `disable_rewards || self.is_pre_consensus()` branch returns early)
- Permanently prevents the sequencer from distributing block-N rewards to any staker [6](#0-5) 

Because `last_reward_block` is global, a single attacker transaction per block silently zeroes out all stakers' yield for that block. This constitutes **permanent freezing of unclaimed yield** (High impact per the allowed scope).

### Likelihood Explanation
The function is publicly callable by any non-zero address with no role or stake requirement. The only cost is Starknet transaction fees. A motivated attacker can sustain this indefinitely. The spec's "Only starkware sequencer" constraint is entirely absent from the contract code, making this trivially reachable. [7](#0-6) 

### Recommendation
Store the authorized sequencer address in contract storage during construction and add an explicit caller check at the top of `update_rewards`:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

Alternatively, use the existing roles framework (e.g., a `SEQUENCER_ROLE`) consistent with how `update_rewards_from_attestation_contract` restricts its caller via `assert_caller_is_attestation_contract`. [8](#0-7) 

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has passed).
2. A staker with non-zero balance exists at `staker_address`.
3. Attacker (any address) calls in block N:
   ```
   staking.update_rewards(staker_address, disable_rewards: true)
   ```
4. `last_reward_block` is written to N; no rewards are distributed.
5. The sequencer attempts to call `update_rewards(staker_address, disable_rewards: false)` in the same block N — it reverts with `REWARDS_ALREADY_UPDATED`.
6. Block N's per-block STRK rewards for all stakers are permanently lost.
7. Repeat each block to continuously suppress all yield. [9](#0-8)

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

**File:** src/staking/staking.cairo (L1558-1571)
```text
        fn calculate_block_rewards(
            ref self: ContractState,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) -> (Amount, Amount) {
            if curr_epoch > self.last_calculated_epoch.read() {
                self.last_calculated_epoch.write(curr_epoch);
                let block_rewards = reward_supplier_dispatcher.update_current_epoch_block_rewards();
                self.block_rewards.write(block_rewards);
                block_rewards
            } else {
                self.block_rewards.read()
            }
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

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
