### Title
Missing Access Control on `update_rewards` Allows Any Caller to Block Reward Distribution - (`src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can invoke it with `disable_rewards: true`, consuming the per-block `last_reward_block` slot and permanently preventing the legitimate sequencer from distributing rewards for that block.

---

### Finding Description

The protocol specification explicitly restricts `update_rewards` to the Starkware sequencer:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation at `StakingRewardsManagerImpl::update_rewards` performs no such check. It only validates:
1. Contract is not paused (`general_prerequisites`)
2. `current_block_number > last_reward_block` (prevents double-update per block)
3. Staker exists and is active
4. Staker has non-zero balance [2](#0-1) 

There is no `assert_caller_is_sequencer()` or equivalent guard — compare with the analogous check present in `update_rewards_from_attestation_contract`:

```cairo
self.assert_caller_is_attestation_contract();
``` [3](#0-2) 

The `last_reward_block` storage variable is **global** (not per-staker). When any caller invokes `update_rewards` for any `staker_address`, it writes `current_block_number` into `last_reward_block`:

```cairo
self.last_reward_block.write(current_block_number);
``` [4](#0-3) 

Any subsequent call in the same block — including the legitimate sequencer call — will revert with `REWARDS_ALREADY_UPDATED` because `current_block_number > last_reward_block` is no longer satisfied. [5](#0-4) 

---

### Impact Explanation

An attacker calls `update_rewards(any_staker_address, disable_rewards: true)` at the start of every block. This:

1. Writes `last_reward_block = current_block_number` without distributing any rewards (the `disable_rewards || is_pre_consensus()` branch returns early).
2. Causes every subsequent sequencer call in that block to revert with `REWARDS_ALREADY_UPDATED`.
3. Stakers and pool members accumulate zero `unclaimed_rewards_own` for every griefed block.

Sustained over time, this constitutes **permanent freezing of unclaimed yield** for all stakers and delegators — a High-severity impact under the allowed scope.

The `IStakingRewardsManager` interface confirms `update_rewards` is the sole mechanism for consensus-era block reward distribution: [6](#0-5) 

---

### Likelihood Explanation

- The function is publicly callable with no role or address restriction.
- The attacker needs only to submit a transaction before the sequencer's own `update_rewards` call each block — a straightforward front-run on a predictable, recurring operation.
- Gas cost is the only barrier; no capital or privileged access is required.
- The attack is sustainable indefinitely.

---

### Recommendation

Add a caller check analogous to the one used in `update_rewards_from_attestation_contract`. Store the authorized sequencer address in contract storage during construction and assert it on entry:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
```

Alternatively, restrict via the existing `RolesComponent` by assigning a dedicated `SEQUENCER` role and checking it here.

---

### Proof of Concept

1. Deploy the system (staking contract in consensus-rewards mode).
2. Advance to a block where a staker is eligible for rewards.
3. Attacker calls `IStakingRewardsManagerDispatcher::update_rewards(staker_address, disable_rewards: true)` — no special role needed.
4. `last_reward_block` is set to the current block number; no rewards are distributed.
5. Sequencer attempts `update_rewards(staker_address, disable_rewards: false)` in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeat every block: staker's `unclaimed_rewards_own` never increases.

The test suite confirms `update_rewards` is callable without any caller restriction — tests invoke it directly with no `cheat_caller_address` setup: [7](#0-6)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
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

**File:** src/staking/tests/test.cairo (L3514-3516)
```text
    let mut spy = snforge_std::spy_events();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
```
