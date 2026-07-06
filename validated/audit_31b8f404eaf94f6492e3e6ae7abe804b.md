### Title
Unprivileged Caller Can Permanently Freeze All Consensus Rewards by Advancing `last_reward_block` Without Distributing Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

In `update_rewards`, the global accounting variable `last_reward_block` is written **before** the `disable_rewards` early-return check. Because the function enforces a strict one-call-per-block invariant on `last_reward_block`, any unprivileged caller can invoke `update_rewards(valid_staker, disable_rewards: true)` each block to advance the accounting state without ever distributing rewards, permanently freezing all consensus-era yield.

---

### Finding Description

`update_rewards` in `src/staking/staking.cairo` is a public, permissionless function (only `general_prerequisites()` is checked, which enforces non-zero caller and non-paused state — no role gate). [1](#0-0) 

The function enforces that only one reward update may occur per block: [2](#0-1) 

After validating the staker, it **unconditionally writes** `last_reward_block` to the current block number: [3](#0-2) 

Only **after** that write does it check `disable_rewards` and return early without distributing anything: [4](#0-3) 

The result: the accounting state (`last_reward_block`) advances to block N, but no rewards are minted or credited to any staker or pool. Every subsequent call to `update_rewards` in block N will revert with `REWARDS_ALREADY_UPDATED`, making the reward slot for that block permanently unclaimable.

The `last_reward_block` field has no admin reset path anywhere in the contract. [5](#0-4) 

---

### Impact Explanation

This is a **permanent freezing of unclaimed yield** for all stakers and delegators in the consensus-rewards era. An attacker calling `update_rewards(..., disable_rewards: true)` once per block causes every block's worth of consensus rewards to be silently discarded. The `reward_supplier` never receives an `update_unclaimed_rewards_from_staking_contract` call, stakers' `unclaimed_rewards_own` fields are never incremented, and pool `cumulative_rewards_trace` entries are never appended. The loss compounds every block and is irrecoverable without a contract upgrade.

---

### Likelihood Explanation

The attack requires only:
1. Knowledge of any one active, non-zero-balance staker address (publicly readable from on-chain events).
2. A single low-cost transaction per block on Starknet (gas is cheap).
3. No capital, no privileged role, no front-running precision — just a bot submitting one tx per block.

The attack becomes relevant the moment `consensus_rewards_first_epoch` is reached. It is trivially automatable.

---

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` / `is_pre_consensus` guard, so that the accounting state is only advanced when rewards are actually distributed:

```cairo
// Update last block rewards.
// self.last_reward_block.write(current_block_number);  // REMOVE from here

if disable_rewards || self.is_pre_consensus() {
    return;
}

// Only advance the block pointer when rewards are actually distributed.
self.last_reward_block.write(current_block_number);

// ... rest of reward distribution logic
```

Alternatively, add a role gate (e.g., `only_operator`) to `update_rewards` so that `disable_rewards: true` cannot be weaponised by an arbitrary caller.

---

### Proof of Concept

1. Consensus rewards become active (`current_epoch >= consensus_rewards_first_epoch`).
2. Attacker deploys a bot. Each block, the bot calls:
   ```
   staking.update_rewards(staker_address=<any_valid_staker>, disable_rewards=true)
   ```
3. Inside `update_rewards`:
   - Line 1485: `last_reward_block` ← current block number. ✓ (state advanced)
   - Line 1487: `disable_rewards == true` → early return. ✗ (no rewards distributed)
4. Any legitimate call to `update_rewards` in the same block hits the assertion at line 1454–1458 and reverts.
5. Repeated every block: **zero consensus rewards are ever distributed** to any staker or pool, permanently freezing all unclaimed yield. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-187)
```text
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1449-1452)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
