### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary
`update_rewards` is documented as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any address can call it with `disable_rewards: true` every block, consuming the single global `last_reward_block` slot without distributing rewards, permanently denying yield to all stakers and delegators.

### Finding Description
The spec for `update_rewards` states:

> **Access control:** Only starkware sequencer.

However, the implementation's only gate is `general_prerequisites()`:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

There is no sequencer check. The full `update_rewards` body:

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
    // Update last block rewards.
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;
    }
    ...
}
``` [2](#0-1) 

Two properties combine to create the vulnerability:

1. **`last_reward_block` is a single global storage variable** — not keyed per staker. One call per block for any staker address blocks all other stakers from receiving rewards in that block.
2. **`disable_rewards: true` updates `last_reward_block` but skips reward distribution** — the write at line 1485 happens unconditionally before the early-return guard at line 1487. [3](#0-2) 

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block permanently prevents any staker from ever accumulating new consensus-phase rewards.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Once consensus rewards are active, all staker and delegator yield accrues exclusively through `update_rewards`. If an attacker calls it with `disable_rewards: true` every block, no rewards are ever distributed to `unclaimed_rewards_own` or to delegation pools. Stakers and delegators lose all future yield permanently with no recovery path (the attacker only needs to keep calling once per block).

### Likelihood Explanation
**High.** The entry point is fully public (no role, no fee, no stake required). A single EOA with negligible gas budget can call this once per block indefinitely. The attack is cheap, permissionless, and requires no special knowledge beyond the ABI. The only precondition is that consensus rewards are active (`!is_pre_consensus()`), which is the intended production state. [4](#0-3) 

### Recommendation
Add a sequencer-only access control check at the top of `update_rewards`, consistent with the spec. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.roles.only_sequencer(); // enforce spec: "Only starkware sequencer"
    ...
}
```

Alternatively, if a dedicated sequencer role does not yet exist in `RolesComponent`, introduce one and grant it only to the Starkware sequencer address.

### Proof of Concept

```
// Attacker script — runs once per block, zero stake required
loop every block:
    staking.update_rewards(
        staker_address = <any valid active staker>,
        disable_rewards = true
    )
    // last_reward_block is now set to current block
    // REWARDS_ALREADY_UPDATED fires for any legitimate sequencer call this block
    // No rewards distributed; all stakers and delegators earn zero yield
```

The spec confirms the intended guard: [5](#0-4) 

The code confirms the guard is absent: [6](#0-5)

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

**File:** src/staking/staking.cairo (L1794-1797)
```text
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2378-2381)
```text
        fn is_pre_consensus(self: @ContractState) -> bool {
            let first_epoch = self.consensus_rewards_first_epoch.read();
            first_epoch.is_zero() || self.get_current_epoch() < first_epoch
        }
```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
