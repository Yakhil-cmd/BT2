### Title
Missing Caller Authorization on `update_rewards` Allows Anyone to Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` to consume the per-block reward slot without distributing rewards, permanently blocking the sequencer from issuing rewards for that block.

### Finding Description

The spec for `update_rewards` explicitly states:

> **Access control:** Only starkware sequencer.

However, the implementation at `src/staking/staking.cairo` lines 1447–1507 performs no `get_caller_address()` check whatsoever. The only guards are:

1. `general_prerequisites()` — contract not paused
2. `current_block_number > self.last_reward_block.read()` — one call per block
3. Staker existence and activity checks [1](#0-0) 

The critical state mutation is at line 1485: `self.last_reward_block.write(current_block_number)`. This write happens **before** the `disable_rewards` branch check at line 1487. [2](#0-1) 

`last_reward_block` is a **single global storage variable** (not keyed per staker). Once it is written to block N by any caller, the `REWARDS_ALREADY_UPDATED` assertion prevents any further call — including the legitimate sequencer call — for that block. [3](#0-2) 

Contrast this with every other privileged function in the system, which all enforce caller identity:

- `update_rewards_from_attestation_contract` asserts `CALLER_IS_NOT_ATTESTATION_CONTRACT`
- `update_unclaimed_rewards_from_staking_contract` in `reward_supplier.cairo` asserts `CALLER_IS_NOT_STAKING_CONTRACT`
- `claim_rewards` in `reward_supplier.cairo` asserts `CALLER_IS_NOT_STAKING_CONTRACT`
- `update_current_epoch_block_rewards` asserts `CALLER_IS_NOT_STAKING_CONTRACT` [4](#0-3) 

The spec confirms `update_rewards` is intended to be sequencer-only: [5](#0-4) 

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` at block N:

1. Sets `last_reward_block = N` globally.
2. Returns early — no rewards are distributed.
3. The sequencer's subsequent call for block N reverts with `REWARDS_ALREADY_UPDATED`.
4. All stakers and their delegators receive zero rewards for block N.

If the attacker repeats this every block (a sustained front-running griefing), **all staker and delegator unclaimed yield is permanently frozen**. Even intermittent attacks cause partial yield loss. No profit is required; the cost is only gas per block.

This matches the allowed impact: **Permanent freezing of unclaimed yield or unclaimed royalties**.

### Likelihood Explanation

The function is publicly callable with no access restriction. Any address holding a small amount of gas can call it once per block. The only precondition is that a valid, active staker address exists — trivially satisfied on a live network. The attack requires no privileged access, no leaked keys, and no external dependencies.

### Recommendation

Add a sequencer-only caller check at the top of `update_rewards`, analogous to the pattern used throughout the rest of the system:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    self.general_prerequisites();
    // ...
}
```

The sequencer address should be stored at initialization and exposed via a governance-controlled setter, consistent with how `attestation_contract` is stored and checked in `update_rewards_from_attestation_contract`.

### Proof of Concept

1. Deploy the staking system and advance K epochs so a staker has effective balance.
2. Activate consensus rewards via `set_consensus_rewards_first_epoch`.
3. At block N, call `update_rewards(staker_address, disable_rewards: true)` from any EOA.
4. Observe `last_reward_block` is now N.
5. Attempt `update_rewards(staker_address, disable_rewards: false)` from the sequencer address at block N — it reverts with `REWARDS_ALREADY_UPDATED`.
6. Staker's `unclaimed_rewards_own` remains unchanged; no rewards were distributed for block N.
7. Repeat step 3 every block to permanently suppress all consensus reward distribution. [6](#0-5)

### Citations

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

**File:** src/reward_supplier/reward_supplier.cairo (L189-202)
```text
        fn update_unclaimed_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount,
        ) {
            assert!(
                get_caller_address() == self.staking_contract.read(),
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );

            let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
            self.unclaimed_rewards.write(unclaimed_rewards);
            // Request funds from L1 if needed.
            self.request_funds(:unclaimed_rewards);
        }
```

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
