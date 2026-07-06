### Title
Unrestricted `update_rewards` Allows Any Caller to Permanently Block All Stakers' Consensus Rewards Per Block - (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` in `staking.cairo` has **no caller access control** despite the protocol specification explicitly requiring "Only starkware sequencer." Any unprivileged address can call it with `disable_rewards: true` to consume the global `last_reward_block` slot for the current block without distributing any rewards. This permanently prevents the legitimate sequencer from distributing consensus rewards for that block to all stakers.

---

### Finding Description

The `update_rewards` function writes to the global `last_reward_block` storage variable **before** deciding whether to distribute rewards: [1](#0-0) 

The critical sequence is:

1. The function checks `current_block_number > self.last_reward_block.read()` — if this passes, execution continues.
2. It unconditionally writes `self.last_reward_block.write(current_block_number)` at line 1485.
3. **Then** it checks `if disable_rewards || self.is_pre_consensus() { return; }` — returning early without distributing any rewards.

There is no `assert_caller_is_sequencer()` or equivalent guard anywhere in this function. Compare this to `update_rewards_from_attestation_contract`, which correctly enforces: [2](#0-1) 

The spec explicitly states the access control for `update_rewards` is "Only starkware sequencer": [3](#0-2) 

Because `last_reward_block` is a **single global storage slot** (not per-staker), a single attacker call for any valid staker blocks the sequencer from distributing rewards to **all** stakers for that block.

The test suite confirms no caller restriction exists — `update_rewards` is called throughout tests without any `cheat_caller_address` spoofing to a privileged address: [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who front-runs the sequencer's `update_rewards` call every block with `update_rewards(any_valid_staker, disable_rewards: true)` causes:

- `last_reward_block` is set to the current block by the attacker's transaction.
- The sequencer's subsequent call for the same block reverts with `REWARDS_ALREADY_UPDATED`.
- **All stakers** miss their consensus block rewards for that block.
- Repeated every block → permanent, complete denial of consensus rewards for the entire protocol.

The `last_reward_block` guard is global: [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

**High.** The attack requires:
- No special role, key, or privilege — any EOA suffices.
- Only gas cost per block.
- A single valid staker address (publicly readable from chain state).
- Trivial automation: monitor mempool for the sequencer's `update_rewards` call and front-run it.

The attacker has no profit motive but causes direct, measurable damage to all stakers and the protocol.

---

### Recommendation

Add a sequencer-only caller check at the top of `update_rewards`, mirroring the pattern used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // <-- add this
    ...
}
```

Alternatively, move the `last_reward_block.write(...)` to **after** the `disable_rewards` / `is_pre_consensus()` guard so that a no-op call does not consume the block slot.

---

### Proof of Concept

```
1. Consensus rewards are active (post-consensus epoch).
2. Attacker picks any valid staker_address S from on-chain state.
3. At block N, attacker submits:
       update_rewards(staker_address: S, disable_rewards: true)
   → last_reward_block is written to N.
   → Function returns early; no rewards distributed.
4. Sequencer submits:
       update_rewards(staker_address: S, disable_rewards: false)
   → Reverts: "REWARDS_ALREADY_UPDATED" (current_block_number == last_reward_block).
5. All stakers miss block N rewards.
6. Attacker repeats every block → permanent freeze of all consensus rewards.
```

The analog to the maven.move bug is exact: just as any caller could pass the wrong `ASSET` type to pop an order without executing it (consuming the queue slot), here any caller passes `disable_rewards: true` to consume the global `last_reward_block` slot without distributing rewards — permanently blocking the legitimate executor.

### Citations

**File:** src/staking/staking.cairo (L1397-1402)
```text
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
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

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/staking/tests/test.cairo (L3515-3516)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
```
