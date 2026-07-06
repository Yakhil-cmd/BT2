### Title
Missing Access Control on `update_rewards` Allows Any Caller to Redirect Block Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `StakingRewardsManager` implementation is documented as restricted to "Only starkware sequencer" but has **no caller check in the actual code**. Any address can call it, choosing which staker receives the current block's rewards. An attacker who is a registered staker can front-run the sequencer's intended call, directing the block's reward distribution to themselves and causing the intended staker to permanently lose that block's unclaimed yield.

### Finding Description
The spec at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

However, the implementation in `src/staking/staking.cairo` at lines 1449–1507 contains no such check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only checks pause state
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ← no get_caller_address() == sequencer check
    ...
    self.last_reward_block.write(current_block_number);
    ...
    self._update_rewards(...);
}
```

The only guard is `REWARDS_ALREADY_UPDATED`, which enforces **at most one call per block** — not **who** may make that call. Once any caller executes `update_rewards` for a given block, `last_reward_block` is set and every subsequent call in that block reverts. The sequencer's intended call is permanently blocked for that block.

The function accepts a caller-supplied `staker_address`, so the attacker chooses which staker receives the block's rewards. With `disable_rewards: false` and their own staker address, the attacker claims their proportional block rewards while the sequencer's intended recipient receives nothing for that block.

### Impact Explanation
**High — Theft of unclaimed yield.**

Block rewards are computed once per block via `calculate_block_rewards` → `reward_supplier_dispatcher.update_current_epoch_block_rewards()` and credited to exactly one staker per block. If the attacker calls `update_rewards(attacker_staker_address, false)` before the sequencer, the attacker's `unclaimed_rewards_own` is increased by their proportional share of that block's rewards, and the intended staker's share is permanently lost — it is never redistributed. This satisfies the "Theft of unclaimed yield" impact category.

Additionally, an attacker can call with `disable_rewards: true` to burn the block's rewards entirely (griefing with no profit motive, Medium impact).

### Likelihood Explanation
Any registered staker can execute this. On Starknet the sequencer controls ordering within a block, but:
- The sequencer is not the only entity that can submit transactions.
- If the sequencer misses a block or is delayed, any external caller can race in.
- A malicious staker can submit the call at the start of every block, consistently front-running the sequencer's intended target.

The entry path requires only holding a valid staker position (no privileged role, no leaked key).

### Recommendation
Add a sequencer-only access control check at the top of `update_rewards`, consistent with the spec:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // enforce spec: "Only starkware sequencer"
    ...
}
```

Alternatively, expose the sequencer address as a stored role (similar to how `assert_caller_is_attestation_contract` is implemented) and assert it here.

### Proof of Concept
1. Attacker registers as a staker with a non-trivial stake.
2. At the start of a new block (before the sequencer acts), attacker calls:
   ```
   IStakingRewardsManager(staking).update_rewards(attacker_address, false)
   ```
3. `last_reward_block` is set to the current block number; attacker's `unclaimed_rewards_own` is increased.
4. Sequencer attempts `update_rewards(intended_staker, false)` — reverts with `REWARDS_ALREADY_UPDATED`.
5. Intended staker's block reward is permanently lost; attacker has claimed their proportional share.

Relevant code locations: [1](#0-0) 

Spec access-control requirement (violated): [2](#0-1) 

`last_reward_block` write that permanently blocks the sequencer's call: [3](#0-2)

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

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
