### Title
Global `last_reward_block` Updated on No-Op `update_rewards` Call Enables Reward-Slot Griefing — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in the Staking contract writes to the **global** `last_reward_block` storage variable even when called with `disable_rewards: true`, which causes an early return with zero rewards distributed. Because the function carries no on-chain access control (the spec mandates "Only starkware sequencer" but the code does not enforce it), any unprivileged caller can consume the single per-block reward slot before the sequencer's legitimate call, permanently suppressing reward distribution for that block.

---

### Finding Description

`update_rewards` is exposed on the public `IStakingRewardsManager` interface and accepts an arbitrary `staker_address` and a `disable_rewards` flag from any caller.

```cairo
// src/staking/staking.cairo  line 1449-1507
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks is_paused
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),   // GLOBAL lock
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // Update last block rewards.  ← written BEFORE the disable_rewards check
    self.last_reward_block.write(current_block_number);   // line 1485

    if disable_rewards || self.is_pre_consensus() {
        return;                                           // line 1487-1489 – no rewards, but slot consumed
    }
    ...
}
```

`last_reward_block` is a **single global** value shared across all stakers:

```cairo
// src/staking/staking.cairo  line 187
last_reward_block: BlockNumber,
```

The spec explicitly states the access control for this function is "Only starkware sequencer" (`docs/spec.md` line 1645), but no such check exists in the implementation. `general_prerequisites()` only asserts the contract is unpaused.

The structural analog to `syncRamping`: just as the `syncRamping` modifier advanced the sync-state variable even when no actual value change occurred (during a ramp), `update_rewards` advances `last_reward_block` even when `disable_rewards: true` produces no reward distribution — consuming the slot and blocking any subsequent legitimate call in the same block.

---

### Impact Explanation

An attacker who submits `update_rewards(any_valid_staker, disable_rewards: true)` before the sequencer's own call in a given block will:

1. Set `last_reward_block` to the current block number.
2. Cause the sequencer's legitimate `update_rewards(attesting_staker, disable_rewards: false)` to revert with `REWARDS_ALREADY_UPDATED`.
3. The attesting staker receives **zero** block rewards for that block.

Repeated across every block this constitutes **permanent freezing of unclaimed yield** for all stakers (High impact per the allowed scope). Even a single-block attack is **temporary freezing of unclaimed yield** (High) or **griefing with damage to users** (Medium).

---

### Likelihood Explanation

The Starknet sequencer is currently centralised and controls transaction ordering, so it can place its own `update_rewards` call first in each block. However:

- The function is unconditionally public on-chain; there is zero cryptographic or contract-level enforcement of the "Only starkware sequencer" rule.
- Any user can submit a valid transaction calling `update_rewards(valid_staker, disable_rewards: true)` at the tail of block N; if the sequencer includes it at the head of block N+1 before its own call (e.g., due to fee ordering, a sequencer bug, or future decentralisation), the attack succeeds.
- The attacker only needs one valid staker address (publicly readable from events/storage) and enough gas to pay fees — no capital at risk.

Likelihood is **medium** given the current centralised sequencer but rises to **high** as the sequencer decentralises.

---

### Recommendation

1. **Add on-chain access control** to `update_rewards` restricting callers to the designated sequencer/attestation address, matching the spec's stated intent.
2. Alternatively, move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard so that a no-op call does not consume the block's reward slot.

---

### Proof of Concept

```
Block N:
  Attacker tx:   update_rewards(staker=VALID_STAKER, disable_rewards=true)
                 → last_reward_block := N
                 → returns early, no rewards distributed

  Sequencer tx:  update_rewards(staker=ATTESTING_STAKER, disable_rewards=false)
                 → assert!(N > N)  ← FAILS with REWARDS_ALREADY_UPDATED
                 → attesting staker earns 0 rewards for block N

Repeat every block → permanent suppression of all staker rewards.
```

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L187-187)
```text
        last_reward_block: BlockNumber,
```

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

**File:** src/staking/interface.cairo (L304-311)
```text
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

**File:** docs/spec.md (L1642-1645)
```markdown
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
