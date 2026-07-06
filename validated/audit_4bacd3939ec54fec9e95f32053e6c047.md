### Title
Missing Access Control on `update_rewards` Allows Any Caller to Freeze Staker Block Rewards - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` is documented as callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can invoke it with `disable_rewards: true` to consume the per-block reward slot before the sequencer does, permanently denying the attesting staker their block rewards for that block.

### Finding Description

The spec explicitly restricts `update_rewards` to the Starkware sequencer:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation, however, performs no caller identity check. After the standard `general_prerequisites()` (pause guard), the only guard is a global `last_reward_block` check:

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
``` [2](#0-1) 

`last_reward_block` is a **global** (not per-staker) storage slot. Once it is written to the current block number, no further call to `update_rewards` can succeed in that block for **any** staker:

```cairo
self.last_reward_block.write(current_block_number);
``` [3](#0-2) 

When `disable_rewards` is `true` (or `is_pre_consensus()` is true), the function returns immediately after writing `last_reward_block`, distributing **zero** rewards:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [4](#0-3) 

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in block N:

1. Writes `last_reward_block = N` with zero rewards distributed.
2. The legitimate sequencer's subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
3. The staker whose turn it was to receive block rewards in block N receives nothing.

Repeated every block, this permanently freezes all consensus block rewards for all stakers. This matches the allowed impact: **Permanent freezing of unclaimed yield** (High).

### Likelihood Explanation

- The function is publicly callable with no authentication.
- The attacker only needs to submit a transaction before the sequencer in each block — a straightforward front-run on Starknet.
- The cost is only gas; there is no capital requirement.
- A single attacker address can grief the entire protocol indefinitely.

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the registered Starkware sequencer address (analogous to the `CALLER_IS_NOT_STAKING_CONTRACT` guard already used in `RewardSupplier`): [5](#0-4) 

Store the sequencer address in contract storage during construction and assert it in `update_rewards` before any state mutation.

### Proof of Concept

1. Deploy the system normally and advance to the consensus rewards epoch.
2. In block N, before the sequencer acts, call:
   ```
   staking.update_rewards(staker_address=<any_active_staker>, disable_rewards=true)
   ```
3. Observe `last_reward_block` is now N and zero rewards were distributed.
4. The sequencer's call `update_rewards(attesting_staker, disable_rewards=false)` in block N reverts with `REWARDS_ALREADY_UPDATED`. [6](#0-5) 
5. Repeat every block to permanently deny all stakers their consensus block rewards.

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1485-1485)
```text
            self.last_reward_block.write(current_block_number);
```

**File:** src/staking/staking.cairo (L1487-1489)
```text
            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/reward_supplier/reward_supplier.cairo (L207-212)
```text
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
```
