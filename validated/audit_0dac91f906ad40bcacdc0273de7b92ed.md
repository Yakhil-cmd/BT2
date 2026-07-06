### Title
Unprivileged Caller Can Permanently Suppress Per-Block Reward Distribution via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` performs no access-control check on the caller. Any unprivileged address can invoke it with `disable_rewards: true`, which advances `last_reward_block` to the current block without distributing any rewards. Because the function enforces a strict "one call per block" invariant, the legitimate block-proposer call for that block is then permanently blocked, causing the staker's yield for that block to be irrecoverably lost.

### Finding Description

`update_rewards` is the V3 consensus-rewards entry point. Its intended caller is the consensus layer (block proposer), which passes `disable_rewards: false` to credit the proposer's rewards, or `disable_rewards: true` to record that the block was processed without reward distribution.

The function validates the *staker* argument thoroughly — it checks existence, migration status, active status, and non-zero balance — but it performs **no validation of the caller**:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only: not paused, caller != zero
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validation ...
    self.last_reward_block.write(current_block_number);   // ← written unconditionally
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits without distributing
    }
    // ... reward calculation and distribution ...
}
```

`last_reward_block` is a **single, protocol-wide** value. Once it is written to `current_block_number`, the `REWARDS_ALREADY_UPDATED` assertion blocks every subsequent call in the same block — including the legitimate proposer call.

The analog to the external report is exact: the function validates one party (the `staker_address` argument) but entirely omits validation of the other party (the `caller_address`), allowing the unchecked party to exploit the function.

### Impact Explanation

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` before the legitimate proposer call in block N:

1. Advances `last_reward_block` to N.
2. Skips all reward computation and distribution.
3. Causes the legitimate proposer's call to revert with `REWARDS_ALREADY_UPDATED`.
4. The block-N rewards are **permanently lost** — there is no mechanism to retroactively credit them.

Repeating this every block eliminates all consensus-phase staker and delegator yield. This matches the allowed impact: **High — Theft of unclaimed yield / Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- The function is publicly callable with no role requirement.
- The attacker only needs to know any one active staker address (trivially obtained from on-chain events such as `NewStaker`).
- On Starknet the sequencer orders transactions; a well-resourced attacker (or the sequencer itself acting adversarially) can reliably front-run the proposer call every block.
- Gas cost is low — a single failed staker-validation path is cheap.

### Recommendation

Restrict `update_rewards` to a trusted caller. The simplest fix is to add a role check (e.g., `only_rewards_manager` or `only_block_proposer`) analogous to the existing `assert_caller_is_attestation_contract` guard used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_rewards_manager();   // new guard
    ...
}
```

Alternatively, split the function: expose a permissionless `record_block` entry point that only advances `last_reward_block`, and a privileged `distribute_block_rewards` entry point that performs the actual reward computation.

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` is set and current epoch ≥ that value).
2. Attacker observes block N is about to be produced.
3. Attacker submits `update_rewards(alice_staker, disable_rewards: true)` — passes all staker checks, writes `last_reward_block = N`, returns early.
4. Legitimate proposer submits `update_rewards(alice_staker, disable_rewards: false)` — hits `assert!(current_block_number > self.last_reward_block.read())` → reverts.
5. Alice and her delegators receive zero rewards for block N; the reward-supplier balance is never decremented for this block, but the yield is simply never credited — it is permanently frozen.

Relevant code locations: [1](#0-0) 

The `last_reward_block` write that locks out subsequent calls: [2](#0-1) 

The `general_prerequisites` guard that is the only access check applied: [3](#0-2) 

The interface declaration confirming no role restriction is specified: [4](#0-3)

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
