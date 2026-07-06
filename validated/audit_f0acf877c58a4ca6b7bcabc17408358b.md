### Title
Missing Access Control on `update_rewards` Allows Anyone to Block Consensus Reward Distribution - (File: `src/staking/staking.cairo`)

### Summary

`update_rewards` in `staking.cairo` is documented as "Only starkware sequencer" but has no such enforcement in code. Any unprivileged caller can invoke it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block and permanently preventing the legitimate sequencer from distributing consensus rewards for that block. Repeated every block, this freezes all staker yield indefinitely.

### Finding Description

`update_rewards` is exposed as a public function under `IStakingRewardsManager`. Its only access gate is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero: [1](#0-0) 

There is no check that the caller is the Starkware sequencer, despite the spec explicitly requiring it: [2](#0-1) 

The function writes to the **global** `last_reward_block` storage slot unconditionally before the `disable_rewards` branch: [3](#0-2) 

Once `last_reward_block` equals the current block number, any subsequent call in the same block — including the legitimate sequencer's call — reverts with `REWARDS_ALREADY_UPDATED`: [4](#0-3) 

`last_reward_block` is a single global field (not per-staker), so one call per block is sufficient to block rewards for every staker simultaneously: [5](#0-4) 

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker calling `update_rewards(valid_staker, disable_rewards: true)` at the start of every block:
1. Sets `last_reward_block = current_block_number` with no reward distribution.
2. Causes the sequencer's legitimate call to revert with `REWARDS_ALREADY_UPDATED`.
3. All stakers earn zero consensus block rewards for that block.

Repeated every block, this permanently freezes all consensus-era yield across the entire protocol. No staker funds are at rest risk, but all unclaimed yield accrual is halted — matching the **High: Permanent freezing of unclaimed yield** impact category.

### Likelihood Explanation

**High.** The attacker needs only:
- A non-zero address (any EOA or contract).
- Any valid, active staker address with non-zero balance (all staker addresses are public via `NewStaker` events).
- Gas to call `update_rewards` once per block.

No capital, no privileged role, no special setup is required. The attack is cheap, repeatable, and fully permissionless.

### Recommendation

Add a sequencer-only access control check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` enforces `assert_caller_is_attestation_contract()`: [6](#0-5) 

Introduce a stored `sequencer_address` (or reuse an existing role) and assert `get_caller_address() == self.sequencer_address.read()` before any state mutation in `update_rewards`.

### Proof of Concept

```
// Attacker script — run once per block before the sequencer acts

// 1. Find any valid active staker (emitted publicly in NewStaker events)
let victim_staker: ContractAddress = <any_active_staker>;

// 2. Call update_rewards with disable_rewards=true — no special role needed
IStakingRewardsManagerDispatcher { contract_address: staking_contract }
    .update_rewards(staker_address: victim_staker, disable_rewards: true);
// last_reward_block is now == current_block_number, no rewards distributed

// 3. Sequencer's legitimate call in the same block now reverts:
//    "REWARDS_ALREADY_UPDATED"
// => All stakers earn zero consensus rewards for this block.

// Repeat every block to permanently freeze all yield.
```

The root cause — `last_reward_block` written before the `disable_rewards` guard with no caller restriction — is a direct analog to the `depositForMember` pattern in the reference report: a public function manipulates reward-accounting state on behalf of (or against) another party, with no authorization check. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
