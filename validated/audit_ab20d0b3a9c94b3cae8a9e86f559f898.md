### Title
Missing Caller Access Control on `update_rewards` Allows Any Address to Permanently Deny Block Rewards - (`File: src/staking/staking.cairo`)

### Summary
`StakingRewardsManagerImpl::update_rewards` has no caller access control check despite the protocol specification requiring it to be callable only by the Starkware sequencer. Any unprivileged address can call it with `disable_rewards: true`, which advances `last_reward_block` without distributing rewards, permanently preventing the legitimate sequencer from crediting that block's rewards to the staker.

### Finding Description
The spec explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation in `StakingRewardsManagerImpl::update_rewards` performs no caller identity check whatsoever:

```cairo
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
    // ... no assert on get_caller_address() ...
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;
    }
    // distribute rewards ...
}
``` [2](#0-1) 

The critical state mutation is that `last_reward_block` is written unconditionally before the `disable_rewards` guard: [3](#0-2) 

Once `last_reward_block` equals the current block number, any subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`: [4](#0-3) 

### Impact Explanation
An attacker calls `update_rewards(victim_staker, disable_rewards: true)` at the start of any block. This:
1. Writes `last_reward_block = current_block_number` with no rewards distributed.
2. Blocks the legitimate sequencer from calling `update_rewards` for that block (it reverts with `REWARDS_ALREADY_UPDATED`).
3. Since block rewards are per-block and there is no catch-up mechanism, the staker's yield for that block is **permanently lost**.

Repeated across every block, this permanently freezes all consensus-phase yield for any targeted staker and their delegators.

**Impact**: High — Permanent freezing of unclaimed yield.

### Likelihood Explanation
The function is public, requires no tokens, no stake, and no special role. Any EOA on Starknet can call it. The only cost is the gas for the transaction. A griefing bot can front-run the sequencer every block at negligible cost.

### Recommendation
Add a sequencer-only access control guard at the top of `update_rewards`, consistent with how `update_rewards_from_attestation_contract` enforces `assert_caller_is_attestation_contract`: [5](#0-4) 

Introduce an analogous `assert_caller_is_sequencer()` check (using the roles component already present in the contract) and call it as the first assertion inside `update_rewards`.

### Proof of Concept
1. Consensus rewards are active (`!is_pre_consensus()`).
2. Attacker (any address) calls `Staking::update_rewards(staker_address: alice, disable_rewards: true)` at block N.
3. `last_reward_block` is set to N; no rewards are credited to Alice.
4. The legitimate sequencer calls `Staking::update_rewards(staker_address: alice, disable_rewards: false)` in the same block N.
5. The call reverts: `current_block_number (N) > last_reward_block (N)` is false → `REWARDS_ALREADY_UPDATED`.
6. Alice receives zero rewards for block N. The attacker repeats this every block. [6](#0-5)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1394-1400)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
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
