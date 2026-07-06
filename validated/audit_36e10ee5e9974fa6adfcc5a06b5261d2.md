### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Staker Yield - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in the staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` every block, permanently preventing a targeted staker from accumulating unclaimed yield.

### Finding Description
The specification at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

However, the implementation of `update_rewards` in `src/staking/staking.cairo` performs no `get_caller_address()` validation whatsoever: [1](#0-0) 

The function only checks:
1. The contract is not paused (`general_prerequisites()`).
2. `current_block_number > self.last_reward_block.read()` — i.e., rewards have not yet been updated this block.
3. The staker exists and has a non-zero balance.

There is no assertion that `get_caller_address() == sequencer_address` or any equivalent privileged-role check. The `last_reward_block` storage variable is written globally (not per-staker): [2](#0-1) 

The early-return path when `disable_rewards` is `true` exits after writing `last_reward_block` but before distributing any rewards: [3](#0-2) 

This is the direct analog of the "open port" pattern from the external report: a sensitive state-mutating endpoint that should be restricted to a single privileged caller is instead open to the entire internet.

### Impact Explanation
An attacker calls `update_rewards(staker_address, disable_rewards: true)` once per block for every block. Each call:
- Writes `last_reward_block = current_block_number`, consuming the one allowed call per block.
- Returns immediately without distributing any rewards.

The legitimate sequencer's subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`: [4](#0-3) 

Because `last_reward_block` is a single global variable, a single attacker transaction per block is sufficient to block **all** stakers from receiving consensus block rewards for that block. Sustained over time this constitutes permanent freezing of unclaimed yield for every staker and their delegators.

**Matched impact**: *High — Permanent freezing of unclaimed yield.*

### Likelihood Explanation
- No special role, key, or privilege is required.
- The call costs only a standard transaction fee.
- The attacker need only submit one transaction per block (≈ every 3 seconds on Starknet).
- There is no economic barrier; the attacker does not need to hold any stake.
- The attack is fully reachable by any public L2 address.

### Recommendation
Add an explicit caller check at the top of `update_rewards`, analogous to the checks already present on `update_rewards_from_attestation_contract` and `update_unclaimed_rewards_from_staking_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    // Add: assert caller is the registered sequencer / app-governor role
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    self.general_prerequisites();
    ...
}
```

The sequencer address should be stored in contract storage and settable only by governance, mirroring the pattern used for `attestation_contract` and `reward_supplier_dispatcher`.

### Proof of Concept
```
// Attacker script — run once per block indefinitely
loop {
    staking.update_rewards(
        staker_address: any_valid_staker,
        disable_rewards: true,   // no rewards distributed
    );
    // last_reward_block is now current_block_number
    // Sequencer's call in the same block → REWARDS_ALREADY_UPDATED
    wait_for_next_block();
}
```

Reference: the spec mandates the restriction at `docs/spec.md` line 1645; the missing check is confirmed absent in the implementation at `src/staking/staking.cairo` lines 1449–1489. The `update_rewards_from_attestation_contract` function shows the correct pattern — it does enforce `CALLER_IS_NOT_ATTESTATION_CONTRACT`: [5](#0-4) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1411-1423)
```text
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_epoch_rewards,
                    btc_total_rewards: btc_epoch_rewards,
                    :strk_total_stake,
                    :btc_total_stake,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```

**File:** src/staking/staking.cairo (L1449-1489)
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
```

**File:** docs/spec.md (L1638-1652)
```markdown
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
