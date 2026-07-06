Looking at the `update_rewards` function in `src/staking/staking.cairo` and comparing it to the spec, I can identify a clear analog to the Alchemix unlimited-accrual bug.

The spec at `docs/spec.md:1644-1645` states `update_rewards` access control is **"Only starkware sequencer"**, but the implementation at `src/staking/staking.cairo:1449-1507` contains **no caller check** — only a global block-number guard (`current_block_number > self.last_reward_block.read()`).

The `last_reward_block` is a single global storage variable (`src/staking/staking.cairo:187`), meaning `update_rewards` can be called exactly **once per block for the entire contract**, regardless of caller. An unprivileged attacker who calls it first in any block consumes that slot, causing the sequencer's intended call for a different staker to revert with `REWARDS_ALREADY_UPDATED`.

---

### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Other Stakers' Yield - (File: `src/staking/staking.cairo`)

### Summary
`update_rewards` is specified as callable only by the Starkware sequencer, but the implementation omits this access control check. Any unprivileged address can call it every block for their own staker, consuming the global `last_reward_block` slot and permanently preventing the sequencer from distributing block rewards to all other stakers.

### Finding Description
The spec (`docs/spec.md:1644-1645`) mandates:
> **Access control:** Only starkware sequencer.

The implementation at `src/staking/staking.cairo:1449-1507` enforces only:

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
    // ... no caller check ...
    self.last_reward_block.write(current_block_number);
    // ... distribute rewards to staker_address ...
}
``` [1](#0-0) 

`last_reward_block` is a single global `BlockNumber` field in storage: [2](#0-1) 

Once written in a block, no further call to `update_rewards` can succeed in that same block for **any** staker. The spec's "Only starkware sequencer" restriction is the sole mechanism intended to prevent abuse of this global slot. [3](#0-2) 

### Impact Explanation
An attacker who is a registered staker calls `update_rewards(attacker_staker_address, false)` at the start of every block. This:

1. Writes `last_reward_block = current_block_number`.
2. Distributes the attacker's own proportional block rewards (no more than they'd normally receive).
3. Causes every subsequent sequencer call for any other staker in that block to revert with `REWARDS_ALREADY_UPDATED`.

Other stakers' block rewards for those blocks are **permanently lost** — they are never accrued into `unclaimed_rewards_own` and never minted. This matches the allowed impact: **High: Permanent freezing of unclaimed yield**. [4](#0-3) 

### Likelihood Explanation
The entry point is fully public — any registered staker can call it. No special role, leaked key, or external dependency is required. The attacker only needs to submit a transaction before the sequencer's `update_rewards` transaction in each block. On Starknet L2, where the sequencer ordering is observable, this is straightforward. The cost is one transaction per block.

### Recommendation
Add a caller check matching the spec. For example, introduce a `sequencer_address` role (or reuse an existing operator role) and assert:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

This mirrors how `update_rewards_from_attestation_contract` correctly enforces its caller restriction via `self.assert_caller_is_attestation_contract()`. [5](#0-4) 

### Proof of Concept

```
// Pseudocode (Starknet Foundry style)
// Attacker is a registered staker with active balance.

fn test_update_rewards_griefing() {
    // Setup: deploy system, stake as attacker, advance K epochs so balance is active.
    let attacker_staker = setup_staker();
    advance_k_epochs();
    start_consensus_rewards();

    // Advance one block so last_reward_block < current_block.
    advance_block(1);

    // Attacker front-runs the sequencer every block.
    // Sequencer intended to call update_rewards(victim_staker).
    // Attacker calls it for themselves first.
    cheat_caller_address(staking_contract, attacker_staker.address);
    staking.update_rewards(attacker_staker.address, false);  // succeeds

    // Sequencer's call for victim now reverts.
    let result = staking_safe.update_rewards(victim_staker.address, false);
    assert_panic_with_error(result, "REWARDS_ALREADY_UPDATED");

    // Victim's block rewards for this block are permanently lost.
    advance_epoch();
    assert!(staking.staker_info(victim_staker.address).unclaimed_rewards_own == 0);
}
```

The test pattern `REWARDS_ALREADY_UPDATED` on a same-block second call is already confirmed by the existing test suite: [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
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

**File:** src/staking/staking.cairo (L1484-1507)
```text
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

**File:** docs/spec.md (L1643-1652)
```markdown
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

**File:** src/staking/tests/test.cairo (L3878-3884)
```text
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
