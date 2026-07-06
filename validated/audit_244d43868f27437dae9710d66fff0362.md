### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Staker Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is documented in the protocol spec as callable only by the Starkware sequencer, but the implementation contains no caller check whatsoever. Any unprivileged address can call it with `disable_rewards=true` every block, permanently consuming the per-block reward slot for every staker and freezing all unclaimed yield.

---

### Finding Description

The spec at `docs/spec.md:1644-1645` explicitly states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo:1449-1507` enforces no such restriction:

```cairo
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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
        self.last_reward_block.write(current_block_number);   // consumes the block slot

        if disable_rewards || self.is_pre_consensus() {
            return;                                           // exits without distributing
        }
        // reward distribution only reached if disable_rewards == false
    }
}
```

There is no `CALLER_IS_NOT_SEQUENCER` error, no `sequencer_address` storage variable, and no `get_sequencer` call anywhere in the codebase (confirmed by grep). The `general_prerequisites()` call only checks the pause flag.

The critical state mutation is `self.last_reward_block.write(current_block_number)` at line 1485, which occurs **before** the `disable_rewards` branch. Once written, the `REWARDS_ALREADY_UPDATED` guard at line 1454-1458 prevents any second call in the same block — including a legitimate sequencer call.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker calls `update_rewards(any_valid_staker, disable_rewards=true)` once per block. Each call:
1. Passes all checks (contract unpaused, staker active, block is new).
2. Writes `last_reward_block = current_block_number`, consuming the slot.
3. Returns immediately without distributing any rewards.

The sequencer's subsequent call for the same block reverts with `REWARDS_ALREADY_UPDATED`. Block rewards for that block are permanently lost — they are never credited to `unclaimed_rewards_own` and never transferred to the staker or pool. Because this can be repeated every block, the entire consensus-phase reward stream can be frozen indefinitely for all stakers.

---

### Likelihood Explanation

**High.** The function is publicly callable with no authentication barrier. A single attacker address with negligible gas cost can front-run the sequencer every block. The attack requires no privileged access, no token balance, and no prior relationship with any staker. The only precondition is that at least one valid, active staker exists — which is always true in a live network.

---

### Recommendation

Add a sequencer-only guard to `update_rewards`. Store the authorized sequencer address at deployment and assert it at the top of the function:

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

Alternatively, expose a setter for the sequencer address (governed by the app governor) and add the corresponding error variant to the error catalogue, mirroring the pattern already used for `CALLER_IS_NOT_ATTESTATION_CONTRACT` in `update_rewards_from_attestation_contract` at line 1400.

---

### Proof of Concept

```
// Attacker runs this every block after consensus rewards activate:
fn test_attacker_blocks_all_rewards(attacker: ContractAddress, staker: ContractAddress) {
    // Advance to consensus phase
    system.start_consensus_rewards();
    system.advance_k_epochs_and_attest(:staker);

    let rewards_before = staking.staker_info_v1(staker).unclaimed_rewards_own;

    // Attacker (no stake, no role) calls update_rewards with disable_rewards=true
    cheat_caller_address_once(
        contract_address: staking_contract,
        caller_address: attacker,   // completely unprivileged
    );
    staking_rewards_manager.update_rewards(
        staker_address: staker,
        disable_rewards: true,      // skips distribution, but consumes the block slot
    );

    // Sequencer now tries to distribute rewards for this block — reverts
    let result = staking_rewards_manager_safe
        .update_rewards(staker_address: staker, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());

    // Staker's unclaimed rewards are unchanged — rewards for this block are gone
    let rewards_after = staking.staker_info_v1(staker).unclaimed_rewards_own;
    assert!(rewards_after == rewards_before, "rewards were frozen");
}
```

The attack is repeatable every block. Over time, 100% of consensus-phase block rewards can be suppressed for all stakers. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1394-1400)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
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

**File:** docs/spec.md (L1626-1652)
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
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
```
