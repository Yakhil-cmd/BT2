### Title
Global `last_reward_block` Guard With No Access Control Allows Any Caller to Monopolize Reward Updates, Permanently Freezing Other Stakers' Unclaimed Yield - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the staking contract lacks access control and uses a single **global** `last_reward_block` variable instead of per-staker tracking. Any unprivileged user can call `update_rewards` for a chosen staker every block, consuming the one allowed reward-update slot per block and permanently preventing all other stakers from ever receiving their consensus-era block rewards.

---

### Finding Description

`update_rewards` is the consensus-era reward distribution entry point. It contains two compounding flaws that together reproduce the same class of bug as the VetoProposal double-vote: a missing per-entity duplicate guard that lets one caller monopolise a shared counter.

**Flaw 1 – No access control.**
The function calls only `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero. [1](#0-0) 

`general_prerequisites` itself: [2](#0-1) 

The protocol specification explicitly states **"Only starkware sequencer"** for this function's access control: [3](#0-2) 

That restriction is never enforced in code.

**Flaw 2 – Global `last_reward_block` instead of per-staker tracking.**
The guard that prevents double-processing is a single contract-wide `BlockNumber`: [4](#0-3) 

The check and write: [5](#0-4) 

Because `last_reward_block` is global, **exactly one staker can receive rewards per block**. Whichever address calls `update_rewards` first in a block wins; every other staker is locked out for that block.

**Attack path:**

1. Consensus rewards are active (`!is_pre_consensus()`).
2. Attacker (who may be staker A themselves) calls `update_rewards(staker_A, false)` at block N → staker A receives block rewards, `last_reward_block = N`.
3. Attacker calls `update_rewards(staker_A, false)` at block N+1 → staker A receives block rewards again, `last_reward_block = N+1`.
4. Staker B calls `update_rewards(staker_B, false)` at block N+1 → **reverts** with `REWARDS_ALREADY_UPDATED`.
5. Repeat every block: staker B's `unclaimed_rewards_own` is never incremented; their yield is permanently frozen.

The `_update_rewards` internal function that actually credits rewards: [6](#0-5) 

Because `update_rewards` is never called for staker B, the `staker_info.unclaimed_rewards_own += staker_rewards` line at line 2362 is never reached for them.

---

### Impact Explanation

**Permanent freezing of unclaimed yield** for every staker except the one the attacker targets. The attacker can sustain the attack indefinitely (one transaction per block). Staker B's accrued consensus rewards are never credited and can never be claimed, constituting a permanent loss of yield. This matches the **High** impact tier: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

---

### Likelihood Explanation

The entry point is fully public — any non-zero address can call `update_rewards`. No privileged role, leaked key, or external dependency is required. The attacker only needs to submit one transaction per block, a cost that is partially or fully offset by the block rewards they receive for staker A. Any staker with a financial incentive to suppress a competitor's rewards can execute this attack.

---

### Recommendation

Apply either (or both) of the following fixes:

1. **Add access control** — restrict `update_rewards` to the Starknet sequencer address (readable via `starknet::get_execution_info().block_info.sequencer_address`), matching the specification.

2. **Replace the global guard with a per-staker mapping** — change `last_reward_block: BlockNumber` to `last_reward_block: Map<ContractAddress, BlockNumber>` so each staker has an independent duplicate-call guard, analogous to the `hasVoted[party][proposalId][address]` fix recommended in the VetoProposal report.

---

### Proof of Concept

```
Setup:
  - Consensus rewards are active.
  - Staker A and Staker B both have effective stake (K epochs have passed).
  - Attacker controls Staker A's address.

Block 100:
  Attacker calls update_rewards(staker_A, false)
  → last_reward_block = 100
  → staker_A.unclaimed_rewards_own += block_rewards_A  ✓

Block 101:
  Attacker calls update_rewards(staker_A, false)
  → last_reward_block = 101
  → staker_A.unclaimed_rewards_own += block_rewards_A  ✓

  Staker B calls update_rewards(staker_B, false)
  → assert!(101 > 101) FAILS → REWARDS_ALREADY_UPDATED  ✗

Block 102, 103, … (attacker repeats every block):
  Staker B can never call update_rewards successfully.
  staker_B.unclaimed_rewards_own remains 0 forever.
  Staker B calls claim_rewards → receives 0 STRK.
```

Relevant storage and guard: [4](#0-3) [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1485)
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2313-2376)
```text
        fn _update_rewards(
            ref self: ContractState,
            staker_address: ContractAddress,
            strk_total_rewards: Amount,
            btc_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            btc_total_stake: NormalizedAmount,
            mut staker_info: InternalStakerInfoLatest,
            staker_pool_info: StoragePath<InternalStakerPoolInfoV2>,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) {
            // Calculate self rewards.
            let staker_own_rewards = self
                .calculate_staker_own_rewards(
                    :staker_address, :strk_total_rewards, :strk_total_stake, :curr_epoch,
                );

            // Calculate pools rewards.
            let (commission_rewards, total_pools_rewards, pools_rewards_data) = if staker_pool_info
                .has_pool() {
                self
                    .calculate_staker_pools_rewards(
                        :staker_address,
                        :staker_pool_info,
                        :strk_total_rewards,
                        :strk_total_stake,
                        :btc_total_rewards,
                        :btc_total_stake,
                        :curr_epoch,
                    )
            } else {
                (Zero::zero(), Zero::zero(), array![])
            };

            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
            // Emit event.
            self
                .emit(
                    Events::StakerRewardsUpdated {
                        staker_address, staker_rewards, pool_rewards: pool_rewards_list.span(),
                    },
                );

            // Write staker rewards to storage.
            self.write_staker_info(:staker_address, :staker_info);
        }
```

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
