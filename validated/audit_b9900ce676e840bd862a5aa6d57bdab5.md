### Title
Unprivileged Caller Can Permanently Suppress Consensus Reward Distribution via `update_rewards` with `disable_rewards: true` - (File: `src/staking/staking.cairo`)

### Summary
`IStakingRewardsManager::update_rewards` is a public function with no caller access control. Any unprivileged address can call it with `disable_rewards: true` for any staker every block, advancing the global `last_reward_block` sentinel without distributing rewards. Because the function enforces a one-call-per-block invariant on a single shared storage slot, a griefing attacker can permanently prevent all stakers from ever receiving consensus block rewards.

### Finding Description
`update_rewards` is exposed as a public entry point with no role check beyond `general_prerequisites()`, which only asserts the contract is unpaused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

The function body writes `last_reward_block` unconditionally before checking `disable_rewards`:

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
    ...
    self.last_reward_block.write(current_block_number);   // ← sentinel advanced

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← rewards skipped
    }
    ...
``` [2](#0-1) 

`last_reward_block` is a single global storage slot shared across all stakers: [3](#0-2) 

Because the guard `current_block_number > self.last_reward_block.read()` is checked against this single slot, once any caller advances it in a given block, no other call to `update_rewards` can succeed in that same block for any staker.

The interface definition confirms the function is fully public with no documented caller restriction: [4](#0-3) 

### Impact Explanation
An attacker calls `update_rewards(any_staker_address, disable_rewards: true)` once per block. Each call:
1. Passes all guards (contract unpaused, caller non-zero, block number strictly greater than stored value).
2. Writes `last_reward_block = current_block`.
3. Returns immediately without distributing any STRK or BTC block rewards.

Every legitimate call by any staker or their operational address in that block then reverts with `REWARDS_ALREADY_UPDATED`. Repeated every block, this permanently freezes all unclaimed consensus yield for every staker in the protocol. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation
- The function is fully public; no token, no stake, no role is required.
- The attack costs one cheap transaction per block (~2-second block time on Starknet).
- The attacker has no financial risk and gains a griefing outcome against all stakers simultaneously.
- Likelihood is **High**.

### Recommendation
Restrict who may supply `disable_rewards: true`. The simplest fix is to require that the caller is either the staker's registered operational address or a privileged consensus/sequencer role when `disable_rewards` is `true`. Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the pre-consensus short-circuit internally via `is_pre_consensus()` alone, which already exists:

```cairo
if self.is_pre_consensus() {
    return;
}
``` [5](#0-4) 

### Proof of Concept
1. Consensus rewards are active (`consensus_rewards_first_epoch` is set and current epoch ≥ that value).
2. Attacker (any EOA) calls `Staking::update_rewards(victim_staker, disable_rewards: true)` at the first transaction of every block.
3. `last_reward_block` is set to the current block number; the function returns without distributing rewards.
4. Any subsequent call to `update_rewards` in the same block (by the staker, their operational address, or anyone else) reverts with `REWARDS_ALREADY_UPDATED`.
5. Stakers accumulate zero consensus rewards indefinitely. Their `unclaimed_rewards_own` and pool `cumulative_rewards_trace` are never updated. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
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
