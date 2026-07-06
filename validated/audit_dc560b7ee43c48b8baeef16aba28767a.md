### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Deny Block Rewards — (`File: src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is specified to be callable only by the Starknet sequencer, but the implementation contains **no caller check whatsoever**. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block without distributing any rewards, permanently preventing the sequencer from distributing block rewards for that block.

---

### Finding Description

The specification at `docs/spec.md` line 1644–1645 states:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation in `StakingRewardsManagerImpl::update_rewards` performs only these checks:

1. Contract is not paused (`general_prerequisites`)
2. `current_block_number > self.last_reward_block.read()` (deduplication guard)
3. Staker exists and is active
4. Staker has non-zero balance [2](#0-1) 

There is **no `assert_caller_is_sequencer` or equivalent check**. Compare this with the analogous pattern used correctly elsewhere in the same contract — `assert_caller_is_attestation_contract` for `update_rewards_from_attestation_contract`: [3](#0-2) [4](#0-3) 

The critical state mutation is:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [5](#0-4) 

`last_reward_block` is a **single global storage slot** (not per-staker). Once written for block N, any subsequent call in block N — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`. [6](#0-5) 

The test suite confirms no caller restriction is enforced — `update_rewards` is called in tests without any `cheat_caller_address_once` setup: [7](#0-6) 

---

### Impact Explanation

An attacker calls:

```
update_rewards(staker_address: <any_valid_active_staker>, disable_rewards: true)
```

This:
1. Writes `last_reward_block = current_block_number`
2. Returns immediately without distributing any rewards (due to `disable_rewards = true`)

The sequencer's subsequent call for the same block fails with `REWARDS_ALREADY_UPDATED`. The block's consensus rewards are **permanently lost** — there is no recovery path, no retry mechanism, and no way to retroactively credit the missed block.

Repeated across many blocks, this permanently freezes unclaimed yield for all stakers. This matches the allowed impact: **High: Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- The function is publicly callable with no role check.
- The attacker only needs to submit a valid transaction with any active staker address and `disable_rewards: true`.
- On Starknet, the sequencer controls transaction ordering, which reduces opportunistic front-running. However: (a) the sequencer may not call `update_rewards` every block; (b) the attacker can target blocks where the sequencer has not yet acted; (c) a compromised or malicious sequencer node could exploit this directly.
- The attack requires no funds, no special role, and no prior setup beyond knowing an active staker address (which is public on-chain).

---

### Recommendation

Add a caller check enforcing that only the designated sequencer address (or an equivalent privileged role) can invoke `update_rewards`. Following the existing pattern used for `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // ADD THIS
    ...
}
```

Store the sequencer address in contract storage (set at initialization, updatable by governance) and implement `assert_caller_is_sequencer` analogously to `assert_caller_is_attestation_contract`. [4](#0-3) 

---

### Proof of Concept

1. Deploy the staking system and advance past the consensus rewards activation epoch.
2. Stake as a legitimate staker and wait K epochs for balance to become effective.
3. As an **unprivileged address** (no role, no stake), call:
   ```
   IStakingRewardsManagerDispatcher { contract_address: staking_contract }
       .update_rewards(staker_address: victim_staker, disable_rewards: true)
   ```
4. Observe: call succeeds, `last_reward_block` is set to the current block, zero rewards distributed.
5. The sequencer now attempts `update_rewards(staker_address: victim_staker, disable_rewards: false)` in the same block — it reverts with `REWARDS_ALREADY_UPDATED`.
6. The victim staker's `unclaimed_rewards_own` is unchanged; the block's rewards are permanently lost.

This is directly confirmed by the existing assertion test which shows `REWARDS_ALREADY_UPDATED` fires after a single call in the same block, regardless of who called first: [8](#0-7)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1447-1507)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```

**File:** src/staking/tests/test.cairo (L3876-3884)
```text
    advance_epoch_global();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
