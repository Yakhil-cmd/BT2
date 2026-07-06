### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Staker Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function is documented as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged caller can invoke it with `disable_rewards: true`, consuming the per-block reward slot (`last_reward_block`) without distributing any rewards. This permanently denies stakers and delegators their block rewards for every block the attacker front-runs.

---

### Finding Description

`update_rewards` is the consensus-era reward distribution entry point. Its spec explicitly states:

> **Access control:** Only starkware sequencer. [1](#0-0) 

However, the implementation only calls `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero — no sequencer identity check exists. [2](#0-1) [3](#0-2) 

The function writes `last_reward_block` to the current block number **before** it decides whether to distribute rewards: [4](#0-3) 

Because `last_reward_block` is a single global value (not per-staker), once it is written for block N, the guard `current_block_number > self.last_reward_block.read()` causes every subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`. [5](#0-4) 

An attacker supplies the user-controlled parameter `disable_rewards: true`. This value is never validated against any stored protocol state — there is no stored "sequencer-authorized" flag or nonce that the caller's argument must match. The result is structurally identical to the reported pattern: a user-supplied parameter that is accepted without cross-checking stored authoritative state, causing a downstream operation (reward distribution) to be permanently skipped.

---

### Impact Explanation

Every block in which the attacker front-runs the sequencer's `update_rewards` call results in zero rewards being distributed to stakers and delegators. Because the attack can be repeated every block at negligible cost, all future consensus-era block rewards are permanently frozen. This maps directly to the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- The function is publicly callable by any non-zero address with no role requirement.
- The only cost is gas.
- The attacker needs only a valid (publicly observable) `staker_address` and can monitor the mempool or simply call the function first in every block.
- No privileged access, leaked key, or external dependency is required.

Likelihood is **High**.

---

### Recommendation

Add an access control check inside `update_rewards` that restricts the caller to the authorized sequencer address (stored in contract storage or enforced via a role). For example, add a role such as `REWARDS_MANAGER_ROLE` and assert it at the top of the function, analogous to how `pause` asserts `only_security_agent`. [6](#0-5) 

---

### Proof of Concept

1. Staker stakes and K epochs pass; consensus rewards are active.
2. Attacker observes block N is about to be produced.
3. Attacker calls `update_rewards(valid_staker_address, disable_rewards: true)`.
   - `last_reward_block` is written to N.
   - No rewards are distributed (early return at the `disable_rewards` branch).
4. Sequencer attempts `update_rewards(valid_staker_address, disable_rewards: false)` in block N.
   - Reverts: `current_block_number (N) > last_reward_block (N)` is **false** → `REWARDS_ALREADY_UPDATED`.
5. No block rewards are distributed for block N.
6. Attacker repeats steps 2–5 for every subsequent block.
7. All stakers and delegators permanently receive zero consensus block rewards. [7](#0-6)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
