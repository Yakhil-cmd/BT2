### Title
Unvalidated `disable_rewards` Parameter in `update_rewards` Allows Any Caller to Permanently Block Staker Reward Distribution — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `src/staking/staking.cairo` accepts a caller-controlled `disable_rewards: bool` parameter with no access control. Any unprivileged caller can invoke `update_rewards(staker_address, disable_rewards=true)`, which unconditionally writes `last_reward_block` to the current block number and then returns early, skipping all reward distribution. Because `last_reward_block` is updated before the early-return guard, the legitimate sequencer's subsequent call in the same block is rejected with `REWARDS_ALREADY_UPDATED`, permanently denying the staker their per-block consensus rewards for that block.

---

### Finding Description

`update_rewards` is specified as "Only starkware sequencer" in the protocol spec, but the implementation contains no caller check. The function signature is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
)
```

The critical ordering flaw is that `last_reward_block` is written **before** the `disable_rewards` branch:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← gate consumed here

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← rewards skipped
}
```

An attacker who calls `update_rewards(victim_staker, disable_rewards=true)` in block N:

1. Passes all precondition checks (staker exists, is active, has non-zero balance).
2. Writes `last_reward_block = N`.
3. Returns without distributing any rewards.

The sequencer's legitimate call in block N then hits:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

and reverts. The staker's rewards for block N are permanently lost. Repeating this every block eliminates all consensus rewards for the targeted staker indefinitely.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Consensus rewards are minted per block. Each block where the attacker front-runs the sequencer with `disable_rewards=true` is a block whose rewards are never computed, never added to `unclaimed_rewards_own`, and never claimable. Because the attack can be repeated every block at low cost (a single transaction per block per targeted staker), the staker's entire stream of future consensus rewards can be frozen permanently. The staker's existing `unclaimed_rewards_own` balance is unaffected, but no new rewards ever accrue.

---

### Likelihood Explanation

**High.** The function is publicly callable with no access control. Staker addresses are enumerable on-chain via the `stakers` vector. The attacker needs only to submit a transaction per block per target, which is economically feasible on Starknet. No privileged access, leaked keys, or external dependencies are required.

---

### Recommendation

Restrict `update_rewards` to the authorized sequencer address. Add an explicit caller check at the top of the function, analogous to how `update_rewards_from_attestation_contract` restricts to the attestation contract:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // add this guard
    ...
}
```

Alternatively, move the `self.last_reward_block.write(current_block_number)` call to **after** the `disable_rewards` branch so that a skipped-reward call does not consume the block's reward slot.

---

### Proof of Concept

**Actors:**
- Alice: honest staker with active consensus rewards
- Bob: unprivileged attacker

**Setup:**
1. Alice has staked STRK and consensus rewards are active (`is_pre_consensus()` returns `false`).
2. `last_reward_block` is currently block N-1.

**Attack (repeated every block):**

1. Block N begins. Bob monitors the mempool.
2. Bob submits `update_rewards(alice_address, disable_rewards=true)` with a competitive gas price.
3. The call passes all precondition checks (Alice is active, has non-zero balance).
4. `last_reward_block` is written to N.
5. The function returns early — no rewards are computed or distributed.
6. The sequencer submits `update_rewards(alice_address, disable_rewards=false)`.
7. The call reverts: `current_block_number (N) > last_reward_block (N)` is false → `REWARDS_ALREADY_UPDATED`.
8. Alice receives zero rewards for block N.

**Outcome:**
- Bob repeats steps 1–8 every block.
- Alice's `unclaimed_rewards_own` never increases after the attack begins.
- Alice's entire future consensus reward stream is permanently frozen.
- Bob spends only transaction fees; no profit is required.

**Relevant code locations:** [1](#0-0) [2](#0-1)

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
