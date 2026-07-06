### Title
Unprivileged Caller Can Permanently Freeze All Staker Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` has no caller access control in the implementation despite the spec requiring "Only starkware sequencer." Because `last_reward_block` is written unconditionally before the `disable_rewards` guard, any unprivileged address can call `update_rewards(valid_staker, disable_rewards: true)` on every block to consume the single per-block reward slot without distributing any rewards, permanently freezing unclaimed yield for all stakers.

### Finding Description

`update_rewards` in `staking.cairo` is the sole entry point for distributing consensus-phase block rewards. Its implementation enforces a single-call-per-block invariant via `last_reward_block`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause state
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // Update last block rewards.  <-- written BEFORE disable_rewards check
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits with no rewards distributed
    }
    ...
``` [1](#0-0) 

The spec documents the intended access control as "Only starkware sequencer": [2](#0-1) 

However, `general_prerequisites` does not enforce this. The test suite confirms `update_rewards` is callable by any address without caller spoofing: [3](#0-2) 

The `IStakingRewardsManager` interface definition also carries no access-control annotation: [4](#0-3) 

### Impact Explanation

Because `last_reward_block` is written before the `disable_rewards` branch, a single call with `disable_rewards: true` consumes the entire per-block reward slot. Every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. An attacker who front-runs the legitimate sequencer call on every block prevents all stakers from ever accumulating `unclaimed_rewards_own`, permanently freezing unclaimed yield. This matches the allowed impact: **Permanent freezing of unclaimed yield**. [5](#0-4) 

### Likelihood Explanation

The attack requires no stake, no special role, and no capital. Any EOA can submit a transaction per block. On Starknet, transaction ordering within a block is sequencer-controlled, but the sequencer itself is the intended caller — meaning a malicious actor who is not the sequencer can race to submit first. The cost is only gas per block. The attack is repeatable indefinitely with no profit motive required, making it a pure griefing vector.

### Recommendation

Add an explicit caller check at the top of `update_rewards`, consistent with the spec:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
}
```

Alternatively, move `self.last_reward_block.write(current_block_number)` to after the `disable_rewards` guard so that a no-op call does not consume the per-block slot.

### Proof of Concept

1. Consensus rewards are active (`!is_pre_consensus()`).
2. At the start of block N, attacker calls `staking.update_rewards(any_valid_staker, disable_rewards: true)`.
3. `last_reward_block` is set to N; function returns immediately with no rewards distributed.
4. The legitimate sequencer attempts `update_rewards(staker, disable_rewards: false)` — reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat every block. All stakers' `unclaimed_rewards_own` remain at zero indefinitely. [6](#0-5) [7](#0-6)

### Citations

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

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/staking/tests/test.cairo (L3515-3516)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
```

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
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
