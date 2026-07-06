### Title
Unprivileged Caller Can Redirect or Suppress Per-Block Consensus Rewards via Unguarded `update_rewards` - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the `Staking` contract is callable by any non-zero address with no further access control. It accepts an arbitrary `staker_address` and a `disable_rewards` boolean. Because only one call per block is permitted (enforced by a single global `last_reward_block` slot), an attacker who calls first for a given block can either redirect that block's rewards to their own staker or permanently suppress them by passing `disable_rewards: true`. This is a direct analog to the NFTLootbox race condition: a shared, once-per-slot resource (the block reward) has no ownership enforcement, so the first caller wins it.

---

### Finding Description

`update_rewards` is exposed under `IStakingRewardsManager` with no caller restriction beyond `general_prerequisites` (contract not paused, caller non-zero):

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // consumes the slot

    if disable_rewards || self.is_pre_consensus() {
        return;                                           // no rewards distributed
    }
    ...
    self._update_rewards(:staker_address, ...);           // rewards go to caller-chosen staker
}
``` [1](#0-0) 

The global guard is `last_reward_block`: once any transaction writes the current block number there, every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. [2](#0-1) 

Two independent attack paths exist:

**Path A – Reward Redirection (theft of yield)**
An attacker who holds any valid staker position (minimum stake) calls:
```
update_rewards(attacker_staker_address, disable_rewards: false)
```
before the consensus-designated staker does. The block's full STRK (and BTC) rewards are computed against `attacker_staker_address`'s balance and credited to the attacker's `unclaimed_rewards_own` and their pool. The legitimate staker's call then reverts. [3](#0-2) 

**Path B – Reward Suppression (permanent freeze of yield)**
An attacker calls:
```
update_rewards(any_valid_staker, disable_rewards: true)
```
The slot is consumed (`last_reward_block` updated) but the early-return branch fires before `_update_rewards`, so no rewards are distributed to anyone for that block. The reward supplier's unclaimed counter is never incremented for this block, and the funds are permanently stranded. [4](#0-3) 

The `_update_rewards` internal function, which performs the actual accounting and transfer, is only reached when `disable_rewards == false` and consensus rewards are active. [5](#0-4) 

---

### Impact Explanation

**Path A**: Direct theft of unclaimed yield. The attacker captures block rewards that should have accrued to the consensus-selected staker and their delegators. This maps to the **High** impact tier: *Theft of unclaimed yield*.

**Path B**: Block rewards for the targeted block are permanently unclaimable. This maps to the **High** impact tier: *Permanent freezing of unclaimed yield*.

Both paths can be repeated every block, making the cumulative damage unbounded over time.

---

### Likelihood Explanation

**Medium.** The attacker needs only:
1. A valid staker account with non-zero STRK balance (Path A), or any non-zero address (Path B).
2. To submit their transaction before the consensus-designated staker in the same block.

On Starknet the sequencer is currently centralised, which reduces but does not eliminate ordering risk (the attacker can be the sequencer, or collude with it, or simply submit a transaction at the start of every block). No privileged key, bridge compromise, or external dependency is required.

---

### Recommendation

1. **Restrict the caller**: Only the staker's own address or their registered `operational_address` should be permitted to call `update_rewards` for a given `staker_address`. Add a check such as:
   ```cairo
   let caller = get_caller_address();
   assert!(
       caller == staker_address || caller == staker_info.operational_address,
       "{}",
       Error::UNAUTHORIZED_CALLER,
   );
   ```
2. **Restrict `disable_rewards`**: If `disable_rewards: true` is a legitimate protocol feature (e.g., penalty for non-attestation), gate it behind a privileged role (e.g., `only_security_agent`) rather than allowing any caller to set it.
3. **Alternatively**, move the `last_reward_block` write to *after* the `disable_rewards` early-return so that a suppressed call does not consume the block's reward slot.

---

### Proof of Concept

```
Block N begins.

// Attacker (holds minimum stake, staker_B) submits first:
staking.update_rewards(staker_address: staker_B, disable_rewards: false)
  → last_reward_block := N
  → block rewards calculated for staker_B's balance
  → staker_B.unclaimed_rewards_own += block_rewards
  → pool of staker_B receives pool_rewards

// Legitimate consensus-selected staker_A submits second:
staking.update_rewards(staker_address: staker_A, disable_rewards: false)
  → PANICS: current_block_number (N) is NOT > last_reward_block (N)
  → Error::REWARDS_ALREADY_UPDATED

Result: staker_A and their delegators receive zero rewards for block N.
        staker_B (attacker) receives the full block reward.
```

For Path B, replace the attacker's call with `update_rewards(staker_B, disable_rewards: true)`; the slot is consumed and no rewards are distributed to anyone.

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
