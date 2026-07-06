Based on my investigation, I found a clear analog. The `update_rewards` function in `src/staking/staking.cairo` is specified to be callable "Only starkware sequencer" but has no caller check in the implementation. [1](#0-0) [2](#0-1) 

---

### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Staker Yield - (File: `src/staking/staking.cairo`)

### Summary
`IStakingRewardsManager::update_rewards` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block and permanently preventing all stakers from receiving rewards for that block.

### Finding Description
The spec at `docs/spec.md` line 1645 states:

```
#### access control
Only starkware sequencer.
```

The implementation at `src/staking/staking.cairo` lines 1448–1510 performs no such check:

```cairo
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();                          // only checks pause
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        self.last_reward_block.write(current_block_number);   // global slot consumed
        if disable_rewards || self.is_pre_consensus() {
            return;                                           // no rewards distributed
        }
        ...
    }
}
```

`last_reward_block` is a **single global storage variable**, not per-staker. Once it is written to the current block number, every subsequent call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`, regardless of which staker is targeted. This is confirmed by the flow test at `src/flow_test/test.cairo` lines 2822–2829, which shows that after one call, a second call for the same staker in the same block panics. [3](#0-2) [4](#0-3) 

### Impact Explanation
An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` at the start of every block:

1. Writes `last_reward_block = current_block` without distributing any rewards.
2. Blocks the legitimate sequencer from calling `update_rewards` for any staker in that block (all calls revert with `REWARDS_ALREADY_UPDATED`).
3. The rewards for that block are **permanently lost** — there is no mechanism to retroactively distribute skipped-block rewards.

This constitutes **permanent freezing of unclaimed yield** for all stakers and pool delegators, matching the allowed High impact: *"Permanent freezing of unclaimed yield or unclaimed royalties"*. [5](#0-4) 

### Likelihood Explanation
- No special role, token balance, or prior state is required.
- The function is publicly callable by any EOA or contract on Starknet.
- The attacker only needs to front-run the sequencer's `update_rewards` call each block, which is trivially achievable since Starknet transaction ordering is observable.
- The cost is only the gas for one call per block.

### Recommendation
Add a caller check analogous to `assert_caller_is_attestation_contract` used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer();   // <-- add this
    ...
}
```

Store the authorized sequencer address in contract storage (set during initialization or via a governance function) and assert `get_caller_address() == self.sequencer_address.read()`. [6](#0-5) 

### Proof of Concept

1. Deploy the protocol in consensus-rewards mode (`is_pre_consensus() == false`).
2. At the start of block `N`, any unprivileged address calls:
   ```
   staking.update_rewards(staker_address: <any_valid_staker>, disable_rewards: true)
   ```
3. `last_reward_block` is set to `N`; no rewards are distributed.
4. The legitimate sequencer attempts:
   ```
   staking.update_rewards(staker_address: <any_staker>, disable_rewards: false)
   ```
   → reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat every block. All stakers and pool members accumulate zero rewards indefinitely.

The flow test at `src/flow_test/test.cairo` lines 2817–2829 already demonstrates that `update_rewards` with `disable_rewards: true` produces zero rewards and that a second call in the same block reverts — confirming the mechanism. The missing piece (no caller guard) is visible at `src/staking/staking.cairo` lines 1448–1452. [7](#0-6) [8](#0-7)

### Citations

**File:** docs/spec.md (L1626-1652)
```markdown
### update_rewards
```rust
fn update_rewards(ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool);
```
#### description <!-- omit from toc -->
Calculate and update the current block rewards for the for the given `staker_address`.
Send pool rewards to the pools.
Distribute rewards only if `disable_rewards` is False and consensus rewards already started.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
```

**File:** src/staking/staking.cairo (L1394-1402)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
```

**File:** src/staking/staking.cairo (L1448-1510)
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
    }

    #[generate_trait]
```

**File:** src/flow_test/test.cairo (L2817-2829)
```text
    // Disable rewards = true with consensus off - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: true);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
```
