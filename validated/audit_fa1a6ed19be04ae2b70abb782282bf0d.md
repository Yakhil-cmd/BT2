### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Deny Staker Yield - (File: src/staking/staking.cairo)

---

### Summary

`IStakingRewardsManager::update_rewards` is documented in the protocol specification as callable **only by the Starkware sequencer**, but the on-chain implementation contains **no caller check**. Any unprivileged address can call it with `disable_rewards: true` once per block, consuming the single per-block reward slot and preventing the legitimate sequencer from ever distributing rewards for that block. Sustained over time, this permanently freezes all staker and delegator yield.

---

### Finding Description

The specification at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1449–1507 enforces none of that:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence checks ...

    // ← last_reward_block is written BEFORE the disable_rewards branch
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits with no rewards distributed
    }
    // ... reward calculation and distribution ...
}
```

The critical sequence:

1. `last_reward_block` is updated to the current block unconditionally.
2. If `disable_rewards == true`, the function returns immediately — no rewards are distributed.
3. The guard `current_block_number > self.last_reward_block.read()` is **global** (one slot for all stakers). A single call per block with any `staker_address` and `disable_rewards: true` exhausts the slot for every staker.

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` once per block. The sequencer's subsequent call with `disable_rewards: false` hits `REWARDS_ALREADY_UPDATED` and reverts. No rewards are distributed for that block to any staker or delegator.

---

### Impact Explanation

- **Allowed impact matched**: *Permanent freezing of unclaimed yield* (High) / *Griefing with no profit motive but damage to users or protocol* (Medium).
- All stakers and all delegators across all pools lose their yield for every block the attacker griefs.
- The `unclaimed_rewards_own` field of every staker and the pool balance of every delegation pool stop growing.
- Delegators who rely on yield to cover opportunity cost are directly harmed.

---

### Likelihood Explanation

- Starknet transaction fees are low; one call per block is economically trivial.
- No special role, key, or privileged access is required — any EOA or contract can call `update_rewards`.
- The attacker gains no funds; the motive is pure griefing or competitive sabotage of the staking protocol.
- The attack is fully permissionless and requires no setup beyond knowing a valid active staker address (which is public on-chain).

---

### Recommendation

Add a sequencer-only guard at the top of `update_rewards`, analogous to the `CALLER_IS_NOT_ATTESTATION_CONTRACT` check used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
```

Alternatively, restrict via the existing roles component (e.g., `OPERATOR` role assigned to the sequencer address).

---

### Proof of Concept

```
Block N:
  Attacker tx:   update_rewards(staker=ALICE, disable_rewards=true)
                 → last_reward_block := N
                 → returns early, no rewards distributed

  Sequencer tx:  update_rewards(staker=ALICE, disable_rewards=false)
                 → assert!(N > N)  ← FAILS with REWARDS_ALREADY_UPDATED
                 → reverts, no rewards distributed

Block N+1:
  Attacker repeats → same outcome

Result after K blocks: ALICE.unclaimed_rewards_own unchanged; all pool balances unchanged.
```

The root cause is at: [1](#0-0) 

The spec's access-control requirement that is not enforced: [2](#0-1) 

The global `last_reward_block` write that consumes the per-block slot before the `disable_rewards` branch: [3](#0-2)

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

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
