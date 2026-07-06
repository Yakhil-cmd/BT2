### Title
Missing Caller Authorization on `update_rewards` Allows Any Address to Permanently Freeze Block Rewards - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` is documented as callable only by the Starkware sequencer, but the implementation contains no caller authorization check. Any unprivileged address can call it with `disable_rewards: true` to advance the global `last_reward_block` sentinel without distributing rewards, permanently blocking the sequencer from distributing block rewards for that block to all stakers.

### Finding Description
The `IStakingRewardsManager::update_rewards` function is the consensus-era (V3) mechanism by which the Starkware sequencer distributes per-block staking rewards to a given staker and their pools.

The specification explicitly restricts access:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation at `src/staking/staking.cairo` performs no such check:

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
    ...
    self.last_reward_block.write(current_block_number);   // global sentinel updated

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits without distributing
    }
    ...
``` [2](#0-1) 

The global storage variable `last_reward_block` is a single value shared across all stakers. The guard `current_block_number > self.last_reward_block.read()` enforces that rewards can only be distributed once per block. Once an attacker writes the current block number into `last_reward_block` via a call with `disable_rewards: true`, the sequencer's legitimate call in the same block will revert with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

The only preconditions the attacker must satisfy are:
1. The contract is not paused.
2. A valid, active staker address is supplied (any registered staker works).
3. The current block number is strictly greater than the stored `last_reward_block`.

All three are trivially satisfiable by any public caller.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

When the attacker calls `update_rewards(any_active_staker, disable_rewards: true)`:
- `last_reward_block` is set to the current block number.
- No rewards are computed or transferred.
- The sequencer's subsequent call for the same block reverts with `REWARDS_ALREADY_UPDATED`.
- All stakers lose their block rewards for that block permanently (the block cannot be replayed).

By repeating this every block, an attacker can continuously deny all stakers and their delegators their entire consensus-era reward stream at negligible cost (only gas).

### Likelihood Explanation
**High.** The function is publicly callable with no access restriction. The attack requires no special privilege, no capital, and no coordination. A single transaction per block is sufficient to execute it. The attacker only needs to know any valid active staker address, which is publicly observable on-chain via events.

### Recommendation
Add a sequencer-only caller check at the top of `update_rewards`, analogous to the pattern already used in `update_unclaimed_rewards_from_staking_contract` and `claim_rewards` in `reward_supplier.cairo`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // <-- add this guard
    ...
``` [4](#0-3) 

Alternatively, restrict the interface so that `disable_rewards` can only be `true` when called by the sequencer, and allow any caller only when `disable_rewards` is `false` (so stakers can self-trigger reward distribution without blocking the sequencer path).

### Proof of Concept

1. Consensus rewards are active (post `consensus_rewards_first_epoch`).
2. Attacker observes block `N` is about to be produced.
3. Attacker submits: `staking.update_rewards(staker_address: any_valid_staker, disable_rewards: true)` in block `N`.
4. `last_reward_block` is written to `N`; no rewards are distributed.
5. Sequencer submits its legitimate `update_rewards` call in block `N` — it reverts with `REWARDS_ALREADY_UPDATED`.
6. Block `N` rewards for all stakers are permanently lost.
7. Attacker repeats in block `N+1`, `N+2`, … indefinitely. [5](#0-4) [6](#0-5)

### Citations

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

**File:** src/reward_supplier/reward_supplier.cairo (L205-212)
```text
        fn claim_rewards(ref self: ContractState, amount: Amount) {
            // Asserts.
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
```
