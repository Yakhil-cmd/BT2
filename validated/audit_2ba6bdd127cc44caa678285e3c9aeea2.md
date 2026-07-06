Looking at the `update_rewards` function in `src/staking/staking.cairo` and its interaction with `last_reward_block`, I need to verify whether the spec-mandated access control is actually enforced.

### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Suppress Block Rewards - (File: src/staking/staking.cairo)

### Summary
The `IStakingRewardsManager::update_rewards` function is specified to be callable only by the Starkware sequencer, but the implementation contains no such access control check. Any unprivileged caller can invoke `update_rewards(staker_address, disable_rewards: true)` on any block, consuming the global `last_reward_block` slot without distributing rewards. This permanently denies stakers their block rewards for every block where the attacker front-runs the legitimate sequencer call.

### Finding Description
The spec at `docs/spec.md:1644-1645` explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation in `src/staking/staking.cairo` at `StakingRewardsManagerImpl::update_rewards` performs no caller identity check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only checks pause state
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);  // global slot consumed

    if disable_rewards || self.is_pre_consensus() {
        return;                            // exits without distributing rewards
    }
    ...
}
```

The `last_reward_block` is a **global** storage variable (not per-staker). Once written for a given block number, no further call to `update_rewards` can succeed for that block — any subsequent call reverts with `REWARDS_ALREADY_UPDATED`.

The reward calculation path that is bypassed:

```cairo
let (strk_block_rewards, btc_block_rewards) = self
    .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
self._update_rewards(
    :staker_address,
    strk_total_rewards: strk_block_rewards,
    ...
);
```

`calculate_block_rewards` calls `reward_supplier_dispatcher.update_current_epoch_block_rewards()` on the first block of each epoch, which in turn calls `set_avg_block_duration` and computes per-block STRK and BTC rewards proportional to `avg_block_duration * yearly_mint`. When `disable_rewards: true` is passed, this entire path is skipped and rewards are permanently lost for that block.

### Impact Explanation
Each call to `update_rewards` with `disable_rewards: false` adds exactly one block's worth of rewards to the staker's `unclaimed_rewards_own`. Because `last_reward_block` is global and can only be written once per block, an attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` at block N permanently prevents any reward distribution for block N. There is no recovery mechanism — the block number is consumed and cannot be replayed.

An attacker who does this every block eliminates all consensus-phase staking rewards for all stakers. Even a partial attack (targeting specific high-value blocks or epochs) causes permanent, irrecoverable loss of yield.

**Allowed impact matched**: *Permanent freezing of unclaimed yield or unclaimed royalties.*

### Likelihood Explanation
- No special role, stake, or token balance is required — any EOA can call `update_rewards`.
- The only precondition is that a valid, active staker address exists (trivially satisfied once any staker has staked for K epochs).
- The attacker pays only the gas cost of a single transaction per block.
- The attack is fully deterministic and requires no oracle manipulation or timing luck.

### Recommendation
Add a sequencer-only access control guard at the top of `update_rewards`, consistent with the spec. For example, store the authorized sequencer address in contract storage and assert:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

Alternatively, if the function is intentionally public (e.g., to allow stakers to self-report), the `disable_rewards` parameter must be removed or its effect must be restricted so that only the sequencer can pass `disable_rewards: true`. The global `last_reward_block` slot must not be consumable by an unprivileged caller.

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns false).
2. A valid staker `S` exists with non-zero balance at the current epoch.
3. At block `N`, attacker calls:
   ```
   IStakingRewardsManager(staking_contract).update_rewards(S, disable_rewards: true)
   ```
4. `last_reward_block` is written to `N`. The function returns early without distributing rewards.
5. The legitimate sequencer attempts:
   ```
   IStakingRewardsManager(staking_contract).update_rewards(S, disable_rewards: false)
   ```
6. This reverts with `REWARDS_ALREADY_UPDATED` because `N > N` is false.
7. Staker `S` (and all other stakers, since `last_reward_block` is global) permanently loses block `N`'s rewards.
8. Repeating steps 3–7 every block eliminates all consensus-phase rewards.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** src/reward_supplier/reward_supplier.cairo (L166-187)
```text
        fn update_current_epoch_block_rewards(ref self: ContractState) -> (Amount, Amount) {
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
            self.set_avg_block_duration();
            // Calculate block rewards for the current epoch.
            let minting_curve_dispatcher = self.minting_curve_dispatcher.read();
            let yearly_mint = minting_curve_dispatcher.yearly_mint();
            let avg_block_duration = self.avg_block_duration.read();
            let total_rewards = mul_wide_and_div(
                lhs: yearly_mint,
                rhs: avg_block_duration.into(),
                div: BLOCK_DURATION_SCALE.into() * SECONDS_IN_YEAR.into(),
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW);
            let btc_rewards = calculate_btc_rewards(:total_rewards);
            let strk_rewards = total_rewards - btc_rewards;
            (strk_rewards, btc_rewards)
        }
```
