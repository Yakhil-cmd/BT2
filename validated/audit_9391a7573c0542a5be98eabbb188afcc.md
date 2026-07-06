### Title
Missing Caller Validation on `update_rewards` Allows Anyone to Permanently Block Per-Block Reward Distribution - (File: `src/staking/staking.cairo`)

### Summary

The `update_rewards` function in `src/staking/staking.cairo` is specified to be callable **only by the Starkware sequencer**, but the implementation contains **no caller check whatsoever**. Any unprivileged address can invoke it, consuming the single per-block reward slot and permanently preventing legitimate reward distribution for that block.

### Finding Description

The protocol specification at `docs/spec.md` lines 1626–1652 explicitly states:

> **access control:** Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1447–1507 enforces only three conditions:

1. Contract is not paused (`general_prerequisites()`)
2. `current_block_number > self.last_reward_block.read()` — rewards not yet distributed this block
3. The supplied `staker_address` is a valid, active staker with non-zero balance

There is **no check that `get_caller_address()` equals the sequencer address**. A grep for `sequencer` across all Cairo source files returns zero matches, confirming no such guard exists anywhere in the codebase. [1](#0-0) 

The critical state mutation is at line 1485:

```cairo
self.last_reward_block.write(current_block_number);
```

`last_reward_block` is a **global** storage variable (not per-staker). Once written, the `REWARDS_ALREADY_UPDATED` assertion blocks every subsequent call to `update_rewards` for the remainder of that block. [2](#0-1) 

The spec confirms this is a once-per-block slot: [3](#0-2) 

### Impact Explanation

An attacker calls:

```cairo
update_rewards(staker_address: any_valid_staker, disable_rewards: true)
```

- `last_reward_block` is written to the current block number (line 1485).
- The `disable_rewards: true` branch causes an early return at line 1487 — **zero rewards are distributed**.
- Every subsequent call in the same block (including the sequencer's legitimate call) reverts with `REWARDS_ALREADY_UPDATED`.
- Block rewards are **permanently lost** — there is no mechanism to retroactively distribute rewards for a past block.

Repeated every block, this permanently freezes all consensus-era unclaimed yield for all stakers and their delegators. This matches the allowed impact: **High — Permanent freezing of unclaimed yield**. [4](#0-3) 

### Likelihood Explanation

- **No privileges required**: any externally-owned address or contract can call `update_rewards`.
- **Trivially exploitable**: the attacker only needs to submit a transaction in the target block before the sequencer's reward-distribution transaction.
- **Repeatable**: the attack can be executed every block at negligible cost.
- **No profit motive needed**: pure griefing permanently denies yield to all stakers and delegators.

### Recommendation

Add a sequencer-only guard analogous to the existing `assert_caller_is_attestation_contract` pattern already used in the same file:

```cairo
fn assert_caller_is_sequencer(self: @ContractState) {
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
}
```

Call this at the top of `update_rewards`, before any state mutation. Store the authorized sequencer address during contract initialization and expose a governance-gated setter for rotation. [5](#0-4) 

### Proof of Concept

1. Deploy or identify any valid staker `S` with non-zero balance in the staking contract.
2. In block `N`, before the sequencer submits its `update_rewards` transaction, submit:
   ```cairo
   IStakingRewardsManagerDispatcher { contract_address: staking_contract }
       .update_rewards(staker_address: S, disable_rewards: true);
   ```
3. This succeeds: `last_reward_block` is set to `N`, no rewards are minted or distributed.
4. The sequencer's `update_rewards` call for block `N` reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers and delegators receive zero rewards for block `N`.
6. Repeat every block to permanently freeze all consensus reward accrual. [6](#0-5)

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
