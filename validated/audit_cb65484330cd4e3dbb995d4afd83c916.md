### Title
Unprivileged Caller Can Permanently Freeze All Staker Rewards via `update_rewards` with `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary
`update_rewards` in the `Staking` contract has no access control and accepts a caller-controlled `disable_rewards: bool` parameter. Any non-zero address can call it with `disable_rewards: true` every block, consuming the global `last_reward_block` slot while suppressing reward distribution, permanently freezing unclaimed yield for all stakers.

### Finding Description
`IStakingRewardsManager::update_rewards` is a public function with no caller restriction beyond `general_prerequisites()`, which only checks the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function accepts a `disable_rewards: bool` parameter. After validating the staker and writing the current block number to the **global** `last_reward_block` storage slot, it returns early with no reward distribution when `disable_rewards` is `true`: [2](#0-1) 

The `last_reward_block` field is a single global value (not per-staker): [3](#0-2) 

Because the function asserts `current_block_number > last_reward_block`, only one call per block is permitted across the entire contract: [4](#0-3) 

The access guard `general_prerequisites` imposes no role check: [5](#0-4) 

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block:
1. Writes the current block number into `last_reward_block`, consuming the slot.
2. Returns before any reward calculation or distribution occurs.
3. Prevents any subsequent legitimate call to `update_rewards` for that block (assertion reverts).

Because `last_reward_block` is global, a single attacker call per block denies rewards to **every** staker in the protocol for that block.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Stakers and delegators earn block rewards only when `update_rewards` is called with `disable_rewards: false` during the consensus-rewards phase. If an attacker calls the function with `disable_rewards: true` every block, no rewards are ever accrued. Rewards are not retroactively recoverable; missed blocks are lost permanently. Pool members' `cumulative_rewards_trace` is never updated, so `claim_rewards` in the pool contract will always return zero. [6](#0-5) 

### Likelihood Explanation
**High.** The attack requires:
- No funds or tokens.
- No privileged role.
- One Starknet transaction per block (cheap on L2).
- Knowledge of any currently active staker address (publicly observable on-chain).

A griefing attacker with no profit motive can sustain this indefinitely.

### Recommendation
Restrict `update_rewards` to a trusted caller (e.g., the attestation contract, a designated keeper role, or the staker themselves). Alternatively, remove the `disable_rewards` parameter from the public interface and handle the pre-consensus no-op path internally, so external callers cannot suppress reward distribution.

### Proof of Concept
1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and passed).
2. Attacker (any EOA) monitors the chain for each new block.
3. At block `N`, attacker calls:
   ```
   staking.update_rewards(staker_address=<any_active_staker>, disable_rewards=true)
   ```
4. `last_reward_block` is written to `N`; the function returns before `_update_rewards` is reached.
5. Any legitimate call to `update_rewards` at block `N` reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeat every block. No staker ever accumulates `unclaimed_rewards_own`; no pool ever receives a `cumulative_rewards_trace` update. All `claim_rewards` calls return zero. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/pool/pool.cairo (L569-587)
```text
        fn update_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount, pool_balance: Amount,
        ) {
            self.assert_caller_is_staking_contract();

            // `rewards_info` is initialized in the constructor or in the upgrade proccess,
            // so unwrapping should be safe.
            let (_, last) = self.cumulative_rewards_trace.last().unwrap();
            self
                .cumulative_rewards_trace
                .insert(
                    key: self.get_current_epoch(),
                    value: last
                        + self
                            .compute_rewards_per_unit(
                                staking_rewards: rewards, total_stake: pool_balance,
                            ),
                );
        }
```
