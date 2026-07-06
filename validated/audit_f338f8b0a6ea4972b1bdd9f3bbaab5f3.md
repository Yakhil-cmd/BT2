### Title
Permissionless `update_rewards` with `disable_rewards: true` Permanently Freezes Consensus Yield for All Stakers — (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is callable by any non-zero address. It writes `last_reward_block` to the current block **before** checking the `disable_rewards` flag. An attacker can call it once per block with `disable_rewards: true` and any valid staker address, consuming the per-block reward slot without distributing any rewards. Because the slot is global and single-use per block, all legitimate reward-distribution calls for that block revert with `REWARDS_ALREADY_UPDATED`. Repeated across every block, this permanently freezes all consensus-based unclaimed yield.

---

### Finding Description

`update_rewards` in `StakingRewardsManagerImpl` has no access-control guard beyond `general_prerequisites`, which only asserts the contract is unpaused and the caller is non-zero:

```
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

Inside `update_rewards`, the global `last_reward_block` is written unconditionally before the `disable_rewards` branch:

```
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [2](#0-1) 

Any subsequent call in the same block hits:

```
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

The attacker only needs to supply any currently-active staker address (all staker addresses are public on-chain) and pass `disable_rewards: true`. The staker validity checks that follow are satisfied by any legitimate staker:

```
let staker_info = self.internal_staker_info(:staker_address);
let curr_epoch = self.get_current_epoch();
assert!(
    self.is_staker_active(:staker_address, epoch_id: curr_epoch),
    ...
);
...
assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);
``` [4](#0-3) 

---

### Impact Explanation

`update_rewards` is the sole entry point for distributing per-block consensus rewards to stakers. With one call per block (gas cost only), an attacker permanently prevents all stakers from receiving consensus-based yield. The rewards are never claimed from the `RewardSupplier` and never transferred to any staker or pool. This constitutes **permanent freezing of unclaimed yield** for the entire staker set.

Impact: **High** — Permanent freezing of unclaimed yield.

---

### Likelihood Explanation

- No privileged role, leaked key, or external dependency is required.
- The only prerequisite is a valid active staker address, which is trivially obtained from on-chain events (`NewStaker`).
- The attacker's cost is one transaction per block; on Starknet this is low.
- The attack is fully automated and can run indefinitely.

Likelihood: **Medium** (sustained gas cost is the only barrier).

---

### Recommendation

Restrict `update_rewards` to a trusted caller (e.g., the attestation contract, a designated sequencer address, or the staker/operational address themselves). Alternatively, move the `last_reward_block` write to **after** the `disable_rewards` guard so that a `disable_rewards: true` call does not consume the block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only write last_reward_block when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
``` [5](#0-4) 

---

### Proof of Concept

1. Staker Alice stakes and becomes active (epoch + K passes).
2. Attacker monitors the chain. On every new block N:
   - Calls `update_rewards(staker_address: alice, disable_rewards: true)`.
   - `last_reward_block` is set to N; function returns early — no rewards distributed.
3. Any legitimate call to `update_rewards` for block N (by Alice, a relayer, or the protocol) reverts with `REWARDS_ALREADY_UPDATED`.
4. Repeated indefinitely: Alice and all other stakers accumulate zero consensus rewards despite active participation.

The attacker-controlled entry path is `IStakingRewardsManager::update_rewards` with the caller-supplied `disable_rewards: true` flag — a direct analog to the SSRF pattern where an unvalidated user-supplied parameter causes the server/contract to perform an action (consuming the reward slot) that redirects the outcome away from its intended destination (the stakers). [6](#0-5)

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
