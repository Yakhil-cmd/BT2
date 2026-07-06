### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield and Steal Block Rewards - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `Staking.cairo` is specified to be callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any registered staker can call it every block to claim block rewards at an inflated rate while permanently preventing all other stakers from receiving their consensus rewards, because a single global `last_reward_block` gate is consumed by the attacker's call.

---

### Finding Description

The protocol specification explicitly states:

> **access control**: Only starkware sequencer.

However, the on-chain implementation of `update_rewards` only calls `general_prerequisites()`, which checks:

1. The contract is not paused.
2. The caller is not the zero address.

No role-based access control is applied. [1](#0-0) 

```cairo
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
```

`general_prerequisites` only checks pause state and zero-address: [2](#0-1) 

The function then unconditionally writes `last_reward_block` to the current block number **before** checking `disable_rewards`: [3](#0-2) 

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
```

`last_reward_block` is a **single global value** shared across all stakers. Once any call to `update_rewards` succeeds in block N, every subsequent call in block N reverts with `REWARDS_ALREADY_UPDATED`. This means only one staker can receive block rewards per block. [4](#0-3) 

The intended design is that the sequencer rotates through stakers, calling `update_rewards` for one staker per block. An attacker who is a registered staker can call `update_rewards(attacker_staker, disable_rewards: false)` every block, consuming the single per-block reward slot and preventing the sequencer from distributing rewards to any other staker.

The K-epoch delay (`K = 2`) protects against flash-loan-style balance inflation: [5](#0-4) [6](#0-5) 

But the K-epoch delay does **not** protect against the missing access control on `update_rewards` itself.

---

### Impact Explanation

**High — Theft of unclaimed yield + Permanent freezing of unclaimed yield for other stakers.**

An attacker who is a registered staker calls `update_rewards(attacker_staker, disable_rewards: false)` in every block:

- The attacker receives block rewards every block (instead of once per rotation through all stakers).
- `last_reward_block` is set to the current block, so the sequencer's intended call for the legitimate staker fails with `REWARDS_ALREADY_UPDATED`.
- All other stakers are permanently denied their consensus rewards.

Alternatively, a non-staker attacker can call `update_rewards(any_valid_staker, disable_rewards: true)` every block:

- `last_reward_block` is updated but no rewards are distributed.
- All stakers are permanently denied consensus rewards with no profit to the attacker (griefing).

Both variants match the allowed impact categories: **Theft of unclaimed yield** and **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

**Medium.** Any registered staker (an unprivileged role) can execute the theft variant. The attacker only needs to submit a transaction calling `update_rewards` for their own staker address each block. While the Starkware sequencer controls transaction ordering, the on-chain code imposes no restriction, meaning the vulnerability is present and exploitable if the sequencer includes the attacker's transaction before the system transaction — which is not prevented by any on-chain guard.

---

### Recommendation

Add a role check to `update_rewards` consistent with the protocol specification. Restrict the caller to the designated sequencer address (or a `REWARDS_MANAGER` role), analogous to how `update_rewards_from_attestation_contract` restricts its caller: [7](#0-6) 

```cairo
fn assert_caller_is_attestation_contract(self: @ContractState) {
    assert!(
        get_caller_address() == self.attestation_contract.read(),
        "{}",
        Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
    );
}
```

Apply the same pattern to `update_rewards`:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // add this
    ...
}
```

---

### Proof of Concept

1. Attacker registers as a staker with the minimum stake amount via `stake(...)`.
2. After K epochs, the attacker's balance becomes effective at the current epoch.
3. In block N, the attacker calls `update_rewards(attacker_address, disable_rewards: false)`.
4. The function passes all checks (not paused, caller non-zero, block > `last_reward_block`, staker active with non-zero balance).
5. `last_reward_block` is written to N; block rewards are calculated and credited to the attacker.
6. The sequencer's intended call to `update_rewards(legitimate_staker, ...)` for block N reverts with `REWARDS_ALREADY_UPDATED`.
7. The attacker repeats steps 3–6 in block N+1, N+2, … indefinitely.
8. The attacker accumulates block rewards every block; all other stakers receive zero consensus rewards.

Relevant code path: [8](#0-7) [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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

**File:** src/staking/staking.cairo (L2008-2015)
```text
        fn insert_staker_own_balance(
            ref self: ContractState, staker_address: ContractAddress, own_balance: NormalizedAmount,
        ) {
            self
                .staker_own_balance_trace
                .entry(staker_address)
                .insert(key: self.get_epoch_plus_k(), value: own_balance.to_strk_native_amount());
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

**File:** src/constants.cairo (L12-13)
```text
/// Epoch delay before consensus-related changes (e.g. balances, token activations) take effect.
pub(crate) const K: u8 = 2;
```
