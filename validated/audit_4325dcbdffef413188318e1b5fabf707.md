### Title
Unpermissioned `update_rewards` with `disable_rewards=true` Permanently Skips Block Rewards — (`src/staking/staking.cairo`)

### Summary

The `update_rewards` function in `staking.cairo` unconditionally writes `last_reward_block` to the current block number before checking the `disable_rewards` flag. Because the function has no caller access control, any unprivileged address can call it with `disable_rewards = true`, consuming the one-call-per-block slot without distributing any rewards. The staker's reward for that block is permanently lost.

### Finding Description

`update_rewards` is the consensus-phase entry point for distributing per-block staking rewards. Its logic is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: not-paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // ❌ last_reward_block is written BEFORE the disable_rewards check
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // returns with NO rewards distributed
    }
    // reward calculation and distribution only reached here
    ...
}
``` [1](#0-0) 

`general_prerequisites` enforces only two conditions — contract not paused and caller not zero: [2](#0-1) 

There is no role check, no `only_app_governor`, no `only_security_agent`, and no restriction to the attestation contract. The function is part of the public `IStakingRewardsManager` ABI.

**Root cause (analog to the external report):** In the Arcadia bug, `lastRewardGlobal` was not reset after rewards were transferred, so the internal accounting variable diverged from the external contract's state. Here, `last_reward_block` is written to the current block even when `disable_rewards = true` causes an early return with zero rewards distributed. The internal "last processed block" marker advances, but the corresponding reward accounting never happens — the same class of stale-state / skipped-accounting bug.

**Attack path:**

1. Attacker monitors the mempool or simply calls `update_rewards(victim_staker, true)` at the start of every block.
2. `last_reward_block` is set to the current block number.
3. The legitimate consensus call `update_rewards(victim_staker, false)` for the same block reverts with `REWARDS_ALREADY_UPDATED`.
4. No rewards are ever distributed for that block; the `unclaimed_rewards` counter in `RewardSupplier` is never incremented for those blocks. [3](#0-2) 

The `RewardSupplier.update_unclaimed_rewards_from_staking_contract` is only called inside `_update_rewards`, which is never reached when `disable_rewards = true`: [4](#0-3) 

### Impact Explanation

Every block for which the attacker fires the griefing call, the staker (and their delegators) permanently lose that block's STRK and BTC rewards. There is no retroactive recovery mechanism — `last_reward_block` is a monotonically advancing cursor and there is no way to re-process a past block. This constitutes **permanent freezing of unclaimed yield** for all targeted stakers.

### Likelihood Explanation

The attack requires only a standard Starknet transaction per block (~3 s block time). The attacker needs no special role, no tokens, and no prior setup. The only cost is gas. A well-funded griever can sustain the attack indefinitely. The entry point (`update_rewards`) is a public ABI function with no access control beyond "caller != 0".

### Recommendation

Add an access-control guard so that only the attestation contract (pre-consensus) or a designated consensus contract (post-consensus) may call `update_rewards`. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_consensus_contract(); // add this guard
    ...
```

Alternatively, remove the `disable_rewards` parameter from the public interface and handle the "no reward" case internally based on on-chain state (e.g., missed attestation flag), so the caller cannot influence whether rewards are distributed.

### Proof of Concept

```
Block N:
  Attacker tx:  update_rewards(alice_staker, disable_rewards=true)
    → last_reward_block written to N
    → early return, zero rewards distributed

  Legitimate tx: update_rewards(alice_staker, disable_rewards=false)
    → assert!(N > N) FAILS → REWARDS_ALREADY_UPDATED

Block N+1:
  Attacker tx:  update_rewards(alice_staker, disable_rewards=true)
    → last_reward_block written to N+1
    → early return again

  ... repeated every block ...

Result: alice_staker accumulates zero rewards indefinitely.
        unclaimed_rewards in RewardSupplier never increases for alice.
        alice cannot claim any yield; delegators in alice's pool receive nothing.
```

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L189-202)
```text
        fn update_unclaimed_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount,
        ) {
            assert!(
                get_caller_address() == self.staking_contract.read(),
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );

            let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
            self.unclaimed_rewards.write(unclaimed_rewards);
            // Request funds from L1 if needed.
            self.request_funds(:unclaimed_rewards);
        }
```
