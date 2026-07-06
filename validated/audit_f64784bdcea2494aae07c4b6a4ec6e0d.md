### Title
Missing Access Control on `update_rewards` Allows Any Registered Staker to Permanently Deny Yield to All Other Stakers - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is specified as callable "Only starkware sequencer" but the implementation enforces no such restriction. Combined with a **global** `last_reward_block` guard that allows only one `update_rewards` call per block across the entire contract, any registered staker can call this function for themselves in every block, consuming the single per-block reward slot and permanently denying yield to all other stakers.

---

### Finding Description

The protocol specification explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation of `update_rewards` only calls `general_prerequisites()`, which checks for pause state and a non-zero caller — there is no sequencer identity check: [2](#0-1) 

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only checks: not paused, caller != zero
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
```

`general_prerequisites` is: [3](#0-2) 

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

The critical compounding factor is that `last_reward_block` is a **single global storage variable** — not per-staker: [4](#0-3) 

After any call to `update_rewards` in block N, the contract writes `last_reward_block = N`: [5](#0-4) 

Any subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. This means **the entire contract can only distribute rewards to one staker per block**. If an attacker occupies that slot in every block, all other stakers permanently lose their block rewards.

---

### Impact Explanation

**Impact: High — Permanent freezing of unclaimed yield for all stakers except the attacker.**

The Starknet staking system in consensus-rewards mode distributes per-block rewards to stakers via `update_rewards`. Because `last_reward_block` is global, only one staker receives rewards per block. An attacker who calls `update_rewards(attacker_address, false)` in every block:

1. Receives their own normal proportional rewards (no excess gain).
2. Sets `last_reward_block` to the current block.
3. Causes every sequencer-initiated `update_rewards` call for other stakers in that block to revert with `REWARDS_ALREADY_UPDATED`.
4. Those stakers **permanently** lose rewards for that block — there is no catch-up mechanism.

If sustained across all blocks, every other staker's `unclaimed_rewards_own` stops accumulating entirely.

---

### Likelihood Explanation

**Likelihood: Medium.**

Requirements for the attacker:
- Be a registered staker (call `stake()` with `min_stake`).
- Wait K epochs for their balance to become effective (epoch-delayed balance trace). [6](#0-5) 

Once active, the attack costs one transaction per block. On Starknet, transaction fees are low, making sustained execution economically viable. The attacker has a clear profit motive if they hold a non-trivial stake: by eliminating competitors' reward accumulation, their relative share of total rewards increases over time as other stakers exit.

---

### Recommendation

Add an access control check at the top of `update_rewards` to enforce that only the authorized sequencer address (or a designated role) can call it, consistent with the specification:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer(); // enforce spec: "Only starkware sequencer"
    self.general_prerequisites();
    ...
}
```

Alternatively, introduce a per-staker `last_reward_block` mapping so that one staker's reward update does not block all others.

---

### Proof of Concept

```
1. Attacker calls stake(reward_addr, op_addr, min_stake).
2. Attacker waits K epochs for stake to become effective.
3. In every block B:
     Attacker calls update_rewards(attacker_address, disable_rewards=false).
     → last_reward_block is set to B.
     → attacker.unclaimed_rewards_own += attacker_proportional_block_rewards.
4. Sequencer attempts update_rewards(victim_address, false) in block B:
     → assert!(B > last_reward_block.read()) FAILS → REWARDS_ALREADY_UPDATED panic.
5. victim.unclaimed_rewards_own is never incremented for block B.
6. Repeated every block → victim permanently accumulates zero rewards.
```

The root cause is at: [7](#0-6) 

with the global guard at: [8](#0-7) 

and the missing sequencer restriction documented at: [1](#0-0)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

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
