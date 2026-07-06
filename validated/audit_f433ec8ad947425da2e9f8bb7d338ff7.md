### Title
Unrestricted `disable_rewards` Flag in `update_rewards` Allows Any Caller to Permanently Freeze All Staker Yield — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the `Staking` contract is publicly callable with no access control. Any unprivileged caller can pass `disable_rewards: true` to consume the single per-block reward slot without distributing any rewards, permanently blocking all stakers and delegators from accruing unclaimed yield.

---

### Finding Description

`update_rewards` is an `#[abi(embed_v0)]` function — publicly callable by any address — that enforces a global invariant: only one call per block is permitted, enforced by `last_reward_block`. [1](#0-0) 

The function unconditionally writes `last_reward_block = current_block_number` before checking the `disable_rewards` flag: [2](#0-1) 

When `disable_rewards == true`, the function returns immediately after updating `last_reward_block`, distributing zero rewards. Because `last_reward_block` is already set to the current block, every subsequent call to `update_rewards` in that block reverts with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

There is no `only_*` role guard anywhere in `update_rewards`. The `disable_rewards` parameter has no caller restriction: [4](#0-3) 

**Attack path:**
1. Attacker reads any `NewStaker` event to obtain a valid, active `staker_address`.
2. At the start of every block, attacker calls `update_rewards(valid_staker_address, true)`.
3. `last_reward_block` is set to the current block; no rewards are distributed.
4. All legitimate `update_rewards` calls in that block revert.
5. `unclaimed_rewards_own` in every `InternalStakerInfoLatest` and the `cumulative_rewards_trace` in every pool contract are never updated.

The staker's `unclaimed_rewards_own` field is only incremented inside `_update_rewards`, which is never reached when `disable_rewards` is true: [5](#0-4) 

Pool rewards are similarly frozen because `update_pool_rewards` and `update_rewards_from_staking_contract` on pool contracts are only called from `_update_rewards`: [6](#0-5) 

---

### Impact Explanation

All stakers and pool members are permanently denied unclaimed yield. The `unclaimed_rewards_own` balance in every staker's info struct and the `cumulative_rewards_trace` in every pool contract are never updated, freezing all yield accrual for the entire protocol. This matches **High: Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The attack requires only:
- Knowledge of any valid active staker address (trivially obtained from on-chain `NewStaker` events).
- Gas to call `update_rewards` once per block.

On Starknet, per-transaction gas costs are low. The attack is sustainable indefinitely at minimal cost to the attacker, with no profit motive required.

---

### Recommendation

Add access control to `update_rewards` so that only a designated role (e.g., the block proposer, sequencer, or a `REWARDS_MANAGER` role) can invoke it, or at minimum restrict the `disable_rewards: true` path to a privileged caller. The `disable_rewards` flag should not be settable by arbitrary external callers.

---

### Proof of Concept

```
1. Attacker observes a NewStaker event → obtains valid_staker_address.
2. Each block:
   a. Attacker calls update_rewards(valid_staker_address, disable_rewards=true).
   b. last_reward_block is written to current_block_number (line 1486).
   c. Function returns at line 1489 — zero rewards distributed.
3. Any legitimate call to update_rewards in the same block hits:
      assert!(current_block_number > self.last_reward_block.read(), ...)
   and reverts with REWARDS_ALREADY_UPDATED.
4. unclaimed_rewards_own for all stakers remains frozen.
5. cumulative_rewards_trace in all pool contracts is never updated.
6. Pool members calling claim_rewards receive zero rewards indefinitely.
```

### Citations

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

**File:** src/staking/staking.cairo (L1485-1490)
```text
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

```

**File:** src/staking/staking.cairo (L2362-2362)
```text
            staker_info.unclaimed_rewards_own += staker_rewards;
```

**File:** src/staking/staking.cairo (L2365-2365)
```text
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
```
