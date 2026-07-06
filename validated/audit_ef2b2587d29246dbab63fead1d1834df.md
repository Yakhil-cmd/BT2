### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Deny Block Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true`, permanently consuming the one-call-per-block slot and causing stakers and delegators to lose their consensus block rewards for that block forever.

### Finding Description
The spec explicitly states the access control for `update_rewards`:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation in `StakingRewardsManagerImpl` contains no `get_caller_address()` check at all: [2](#0-1) 

The function accepts a caller-controlled `disable_rewards: bool` parameter. When `disable_rewards` is `true`, the function:
1. Validates the staker exists and is active.
2. **Writes `current_block_number` to `last_reward_block`** — permanently consuming the per-block reward slot.
3. Returns early without distributing any rewards.

Because `last_reward_block` is now set to the current block, any subsequent call in the same block — including the legitimate sequencer call — will revert with `REWARDS_ALREADY_UPDATED`: [3](#0-2) 

The interface definition confirms the function is publicly exposed with no access restriction in code: [4](#0-3) 

### Impact Explanation
Block rewards for the targeted block are **permanently lost**. There is no mechanism to retroactively distribute rewards for a block whose `last_reward_block` has already been recorded. Both the staker's `unclaimed_rewards_own` and the delegation pool's reward balance are never incremented for that block. This constitutes **permanent freezing of unclaimed yield** for stakers and delegators.

### Likelihood Explanation
The attack requires no funds, no privileged role, and no special setup. Any Starknet account can call `update_rewards(staker_address, disable_rewards: true)` on any block. An attacker can target a specific high-value staker repeatedly across every block during the consensus rewards phase, causing sustained, compounding yield loss. The cost to the attacker is only gas fees.

### Recommendation
Add a caller check at the top of `update_rewards` that restricts execution to the authorized sequencer address (stored in contract storage), mirroring the pattern already used for the attestation contract:

```cairo
fn update_rewards(...) {
    self.assert_caller_is_sequencer(); // analogous to assert_caller_is_attestation_contract
    self.general_prerequisites();
    ...
}
``` [5](#0-4) 

### Proof of Concept

1. Consensus rewards are active (post `consensus_rewards_first_epoch`).
2. Staker `S` has been staked for `K` epochs and has non-zero balance.
3. Attacker `A` (any address) calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The function passes all assertions, writes `last_reward_block = current_block`, and returns early — **no rewards distributed**.
5. The sequencer's intended call to `update_rewards(S, false)` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. `S` and its pool members receive zero rewards for this block. The loss is permanent.

This is confirmed by the existing flow test which demonstrates that `disable_rewards: true` with consensus active produces zero rewards, and a same-block retry panics: [6](#0-5)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
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

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```

**File:** src/staking/interface.cairo (L304-311)
```text
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

**File:** src/flow_test/test.cairo (L2882-2894)
```text
    // Disable rewards = true with consensus on - no rewards
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
