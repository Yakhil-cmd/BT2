### Title
Unprivileged Caller Can Permanently Freeze Block Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in `staking.cairo` is publicly callable with no access control beyond a zero-address check. It accepts a `disable_rewards: bool` parameter. When called with `disable_rewards: true`, it unconditionally writes the current block number to the global `last_reward_block` storage slot **before** checking whether rewards should be distributed. Because `last_reward_block` is a single global gate that allows only one `update_rewards` call per block, any unprivileged caller can consume the per-block reward slot without distributing any rewards, permanently freezing unclaimed yield for all stakers and pool members.

### Finding Description

`update_rewards` is the consensus-era reward distribution entry point. Its logic is:

1. Assert `current_block_number > last_reward_block` (one call per block gate).
2. Validate the supplied `staker_address` is active with non-zero balance.
3. **Write `last_reward_block = current_block_number`** — unconditionally.
4. If `disable_rewards || is_pre_consensus()` → **return early, no rewards distributed**.
5. Otherwise, calculate and distribute block rewards to the staker and their pools. [1](#0-0) 

The critical ordering flaw: step 3 (consuming the block slot) happens **before** step 4 (the early-return guard). Once `last_reward_block` is set to the current block, no other call to `update_rewards` can pass the gate in that block.

The function has no role-based access control: [2](#0-1) 

`general_prerequisites()` only checks that the contract is unpaused and the caller is non-zero: [3](#0-2) 

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` once per block. Each call:
- Passes all assertions (staker is valid, block is new).
- Writes `last_reward_block = current_block`.
- Returns early — zero rewards distributed to any staker or pool.
- Blocks the legitimate consensus caller from calling `update_rewards` in the same block (the gate check fails).

Repeating this every block permanently freezes all block-reward accrual for every staker and every delegation pool member in the protocol.

### Impact Explanation

Every block reward for every staker and pool member is permanently lost as long as the attacker sustains the griefing. The `unclaimed_rewards_own` field in each `InternalStakerInfo` and the `cumulative_rewards_trace` in each pool contract never advance. Stakers calling `claim_rewards` receive zero; pool members calling `claim_rewards` receive zero. This constitutes **permanent freezing of unclaimed yield** for the entire protocol. [4](#0-3) [5](#0-4) 

### Likelihood Explanation

- No special role or privilege is required — any non-zero address can call `update_rewards`.
- The attacker only needs to supply any currently-active staker address, which is publicly readable from the `stakers` vector.
- Gas cost on Starknet L2 is low, making sustained per-block griefing economically feasible.
- The attacker has no profit motive but causes total reward loss for all participants.

### Recommendation

Restrict `update_rewards` to a trusted caller (e.g., the attestation contract, a designated sequencer address, or a role such as `REWARD_DISTRIBUTOR`). Alternatively, move the `last_reward_block` write to **after** the `disable_rewards` guard so that a call with `disable_rewards: true` does not consume the block slot:

```cairo
// Move the write AFTER the early-return guard
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only consume the block slot when rewards are actually distributed
self.last_reward_block.write(current_block_number);
// ... distribute rewards
```

This mirrors the fix pattern in the reference report: ensure the state-consuming operation cannot be triggered without the corresponding value-producing operation completing.

### Proof of Concept

```
Block N:
  Attacker calls: staking.update_rewards(staker=any_active_staker, disable_rewards=true)
    → last_reward_block is set to N
    → function returns early, zero rewards distributed
  
  Consensus mechanism calls: staking.update_rewards(staker=legitimate_staker, disable_rewards=false)
    → PANICS: "current_block_number > last_reward_block" fails (N == N)
    → No rewards distributed

Block N+1:
  Attacker repeats the same call.
  ...

Result after K blocks:
  staker.unclaimed_rewards_own == 0  (no rewards ever accrued)
  pool.cumulative_rewards_trace unchanged  (no pool rewards ever forwarded)
  All stakers and delegators receive 0 on claim_rewards()
```

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

**File:** src/staking/staking.cairo (L1611-1629)
```text
        /// Sends the rewards to `staker_address`'s reward address.
        /// Important note:
        /// After calling this function, one must write the updated staker_info to the storage.
        fn send_rewards_to_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            ref staker_info: InternalStakerInfoLatest,
            token_dispatcher: IERC20Dispatcher,
        ) {
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();

            self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
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
