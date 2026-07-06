### Title
Missing Access Control on `update_rewards` Allows Any Caller to Steal Block Rewards - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is callable by any address, despite the protocol specification explicitly requiring "Only starkware sequencer" access. Because `last_reward_block` is a single global storage slot, only one call to `update_rewards` can succeed per block. An attacker can frontrun the sequencer, consume the per-block reward slot for their own staker, and cause the sequencer's intended call to revert — stealing block rewards from the rightful recipient.

---

### Finding Description

The spec at `docs/spec.md:1644–1645` states:

```
#### access control
Only starkware sequencer.
```

However, the implementation of `update_rewards` in `src/staking/staking.cairo` contains no caller check whatsoever:

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
    ...
    self.last_reward_block.write(current_block_number);
    ...
}
```

`general_prerequisites()` only asserts the contract is not paused and the caller is not the zero address — it does **not** restrict the caller to the sequencer.

The storage field `last_reward_block` is a **global** (not per-staker) value:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
```

This means only **one** `update_rewards` call can succeed per block across the entire contract. Once `last_reward_block` is written to the current block number, every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.

The attack path:

1. Attacker monitors the mempool for the sequencer's `update_rewards(victim_staker, disable_rewards: false)` transaction.
2. Attacker frontruns it with `update_rewards(attacker_staker, disable_rewards: false)`.
3. Attacker's call succeeds: `last_reward_block` is set to the current block, and block rewards are distributed to `attacker_staker`.
4. The sequencer's call reverts with `REWARDS_ALREADY_UPDATED` — `victim_staker` receives zero rewards for that block.

---

### Impact Explanation

This is **theft of unclaimed yield**. Block rewards that should accrue to the sequencer-selected staker are instead redirected to the attacker's staker. The victim staker permanently loses the block reward for that block (it is not deferred or recoverable — `last_reward_block` advances and the missed block is never revisited). The attacker profits directly by receiving rewards they were not entitled to.

This maps to the allowed impact: **High — Theft of unclaimed yield**.

---

### Likelihood Explanation

The function is part of the public ABI (`IStakingRewardsManager`), callable by any non-zero address with no special role or token requirement. On Starknet, transaction ordering within a block is controlled by the sequencer, but the sequencer itself is the intended caller — meaning a malicious actor who submits a transaction in the same block before the sequencer's `update_rewards` inclusion can execute this attack. The only constraint is that the attacker must have a valid, active staker with non-zero balance (K epochs after staking), which is a trivially achievable precondition.

---

### Recommendation

Add a caller check to `update_rewards` restricting it to the Starkware sequencer address (or an equivalent privileged role). For example, introduce a stored `sequencer_address` and assert:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

Alternatively, if the sequencer address is not stored on-chain, use the existing roles component to define a `SEQUENCER_ROLE` and gate the function behind it, consistent with how `update_rewards_from_attestation_contract` is gated behind `assert_caller_is_attestation_contract`.

---

### Proof of Concept

```
Block N:
  - Sequencer intends to call: update_rewards(victim_staker, disable_rewards: false)
  - Attacker submits first:    update_rewards(attacker_staker, disable_rewards: false)

Attacker's tx executes first:
  - last_reward_block (global) = N
  - attacker_staker.unclaimed_rewards_own += block_rewards  ✓

Sequencer's tx executes second:
  - assert!(N > last_reward_block.read())  →  assert!(N > N)  →  REVERT: REWARDS_ALREADY_UPDATED

Result:
  - victim_staker receives 0 rewards for block N
  - attacker_staker receives full block rewards for block N
```

The relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1488)
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
```

**File:** docs/spec.md (L1626-1645)
```markdown
### update_rewards
```rust
fn update_rewards(ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool);
```
#### description <!-- omit from toc -->
Calculate and update the current block rewards for the for the given `staker_address`.
Send pool rewards to the pools.
Distribute rewards only if `disable_rewards` is False and consensus rewards already started.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
