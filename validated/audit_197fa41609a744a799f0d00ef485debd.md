### Title
Any Caller Can Invoke `update_rewards` with `disable_rewards: true` to Permanently Deny Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `src/staking/staking.cairo` lacks the access control enforcement that the protocol specification requires ("Only starkware sequencer"). Any unprivileged caller can invoke it with `disable_rewards: true`, which permanently marks the current block as "rewards already updated" by writing `last_reward_block = current_block_number` — without distributing any rewards. Because `last_reward_block` is a monotonically-increasing global state variable, no subsequent call can distribute rewards for that block. This is a direct analog to `cancelOrdersUpTo`: both functions allow an unprivileged caller to advance a monotonically-increasing counter in a way that permanently forecloses a future operation.

---

### Finding Description

`update_rewards` is the sole mechanism for distributing per-block consensus rewards to stakers in V3. Its guard is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

After passing this check, the function unconditionally writes:

```cairo
self.last_reward_block.write(current_block_number);
```

and then branches:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [1](#0-0) 

`last_reward_block` is a single global slot shared across all stakers. Once it is set to block `N`, every call to `update_rewards` in block `N` reverts with `REWARDS_ALREADY_UPDATED`. The rewards for block `N` are permanently lost — there is no mechanism to retroactively distribute them.

The protocol specification explicitly states the access control for this function is **"Only starkware sequencer"**: [2](#0-1) 

However, the implementation contains **no such check**. The function body begins with `self.general_prerequisites()` (a pause/contract-state guard) and the block-number monotonicity check, but no caller identity assertion. This is confirmed by the test suite, which calls `update_rewards` directly from arbitrary test addresses without any `cheat_caller_address_once` role spoofing: [3](#0-2) 

The analog to `cancelOrdersUpTo` is exact:

| `cancelOrdersUpTo` (original) | `update_rewards` (analog) |
|---|---|
| Advances `orderEpoch` (monotonically increasing) | Advances `last_reward_block` (monotonically increasing) |
| Callable by any user | Callable by any address |
| Permanently forecloses future orders | Permanently forecloses block reward distribution for that block |
| Irreversible | Irreversible |

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block:

1. Advances `last_reward_block` to the current block without distributing rewards.
2. Causes every legitimate sequencer call to `update_rewards` in that block to revert with `REWARDS_ALREADY_UPDATED`.
3. All stakers lose their consensus block rewards for that block permanently — the yield is never minted or credited.

Because `last_reward_block` is global (not per-staker), a single attacker call per block denies rewards to **all** stakers simultaneously. The lost yield cannot be recovered; there is no catch-up mechanism.

---

### Likelihood Explanation

**High.** The function is publicly callable with no role restriction. The attack requires only gas. An attacker with a griefing motive (e.g., a competing validator, a protocol adversary) can sustain this indefinitely at minimal cost. The attack is also automatable: a simple bot calling `update_rewards` at the start of every block is sufficient.

---

### Recommendation

Add an access control check at the top of `update_rewards` to restrict callers to the authorized starkware sequencer address, consistent with the protocol specification. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_starkware_sequencer(); // enforce spec requirement
    self.general_prerequisites();
    ...
}
```

Alternatively, if the sequencer address is not stored in the roles component, validate `get_caller_address()` against a stored sequencer address before proceeding.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker (any EOA or contract) calls:
   ```
   IStakingRewardsManager(staking_contract).update_rewards(
       staker_address = <any active staker>,
       disable_rewards = true
   )
   ```
   at block `N`.
3. `last_reward_block` is written to `N`; no rewards are distributed.
4. The legitimate sequencer attempts to call `update_rewards` for the same block `N` — it reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers permanently lose their block `N` rewards.
6. Attacker repeats at block `N+1`, `N+2`, … to continuously deny all staker yield. [4](#0-3) [2](#0-1)

### Citations

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

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
