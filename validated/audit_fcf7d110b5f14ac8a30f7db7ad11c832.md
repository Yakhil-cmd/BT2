### Title
Unprivileged Caller Can Permanently Freeze Staker Unclaimed Yield via `update_rewards(disable_rewards: true)` — (File: src/staking/staking.cairo)

---

### Summary

`update_rewards` in `StakingRewardsManagerImpl` carries no access-control guard. Any address can call it with `disable_rewards: true` for any valid staker, consuming the single per-block reward slot (`last_reward_block`) without distributing rewards. The legitimate consensus-layer call that follows in the same block is then permanently rejected with `REWARDS_ALREADY_UPDATED`, causing the staker to lose block rewards for that block. Repeated front-running across every block permanently freezes the staker's unclaimed yield.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address. [1](#0-0) 

No role, no allowlist, no check that the caller is the attestation contract or any other trusted party.

The function immediately writes the current block number to the global `last_reward_block` storage slot before inspecting `disable_rewards`: [2](#0-1) 

The write at line 1485 happens unconditionally. The `disable_rewards` branch at lines 1487-1489 then returns early without distributing any rewards. Because `last_reward_block` is a single global value shared across all stakers, the slot is now consumed for the entire block. [3](#0-2) 

Any subsequent call to `update_rewards` in the same block — including the legitimate consensus-layer call — hits the assertion at lines 1453-1458 and reverts.

The `disable_rewards` parameter is fully caller-controlled; the public interface exposes it without restriction: [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who front-runs the legitimate `update_rewards` call every block causes the targeted staker to receive zero block rewards indefinitely. The lost rewards are not deferred; they are simply never credited to `staker_info.unclaimed_rewards_own` and never forwarded to delegation pools. Because `last_reward_block` is global, a single griefing transaction per block is sufficient to deny rewards to the targeted staker for that block, with no recovery path. [5](#0-4) 

---

### Likelihood Explanation

**High.** The attack requires only a standard transaction with no special privileges, no capital, and no leaked keys. The attacker needs only to know a valid active staker address (publicly observable on-chain) and submit a transaction with `disable_rewards: true` before the consensus-layer call in each block. This is trivially automatable with a mempool-watching bot or a simple script that submits the griefing call at the start of every block.

---

### Recommendation

Restrict `update_rewards` to a trusted caller. The simplest fix is to add an access-control assertion analogous to `assert_caller_is_attestation_contract`, requiring the caller to be the designated consensus/attestation contract (or a new dedicated rewards-manager role). Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the "no-attest" case inside the attestation contract before it calls the staking contract.

---

### Proof of Concept

1. Staker Alice is active with non-zero balance. The consensus layer is expected to call `update_rewards(alice, false)` once per block to credit her rewards.
2. Attacker Eve monitors the mempool (or simply submits at the start of every block).
3. Eve calls `staking.update_rewards(alice, true)`.
   - `general_prerequisites()` passes (contract not paused, Eve ≠ zero).
   - `current_block_number > last_reward_block` passes (first call this block).
   - `last_reward_block` is written to `current_block_number`.
   - `disable_rewards == true` → function returns early; no rewards credited.
4. The consensus layer's call `update_rewards(alice, false)` arrives in the same block.
   - `current_block_number > last_reward_block` **fails** → reverts with `REWARDS_ALREADY_UPDATED`.
5. Alice receives zero rewards for this block. Eve repeats every block at negligible cost. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1185-1188)
```text
            );

            let to_staker_info = self.internal_staker_info(staker_address: to_staker);

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

**File:** src/staking/staking.cairo (L2349-2376)
```text
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

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
