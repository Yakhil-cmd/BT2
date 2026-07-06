### Title
Missing Caller Validation on `update_rewards` Allows Anyone to Permanently Freeze Staker Yield - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true`, which marks the current block as "already rewarded" and returns without distributing any yield. Because `last_reward_block` is written unconditionally before the `disable_rewards` guard, the sequencer is permanently locked out from distributing rewards for that block.

---

### Finding Description

The protocol specification explicitly restricts `update_rewards` to the Starkware sequencer:

> **access control**: Only starkware sequencer. [1](#0-0) 

The `IStakingRewardsManager` interface exposes `update_rewards` as a public external function with no access-control annotation: [2](#0-1) 

The implementation in `StakingRewardsManagerImpl` performs no `get_caller_address()` check. It only validates that the contract is unpaused, that the block is new, and that the staker is active. Critically, it writes `last_reward_block` to the current block number **before** the `disable_rewards` branch: [3](#0-2) 

Once `last_reward_block` equals the current block, any subsequent call in the same block — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`: [4](#0-3) 

Compare this with `update_rewards_from_attestation_contract`, which correctly enforces its caller restriction: [5](#0-4) 

---

### Impact Explanation

An attacker calling `update_rewards(any_valid_staker, disable_rewards: true)` every block permanently prevents reward distribution for every block they front-run. Stakers and delegators accumulate zero `unclaimed_rewards_own` and zero pool rewards for those blocks. The yield is not deferred — it is lost, because block rewards are calculated per-block and there is no catch-up mechanism. This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators.

**Impact category**: High — Permanent freezing of unclaimed yield.

---

### Likelihood Explanation

The function is callable by any address with no preconditions beyond the contract being unpaused and a valid active staker address existing (both trivially satisfiable). The attacker needs only to submit a transaction in the same block as the sequencer's reward update, which is straightforward on Starknet where transaction ordering within a block is controlled by the sequencer but the mempool is observable. Even a single successful call per block is sufficient to deny all rewards for that block. The attack can be repeated indefinitely at negligible cost.

---

### Recommendation

Add a caller check at the top of `update_rewards`, analogous to the check already present in `update_rewards_from_attestation_contract`. Introduce a stored `sequencer_address` (or reuse an existing privileged role) and assert:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

Place this assertion before the `last_reward_block` write so that unauthorized calls revert without mutating state.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. A valid staker `S` exists with non-zero balance.
3. Attacker observes the mempool and front-runs the sequencer's `update_rewards(S, false)` call.
4. Attacker calls `update_rewards(S, true)` — passes all checks, writes `last_reward_block = current_block`, returns early with no rewards distributed.
5. Sequencer's `update_rewards(S, false)` call reverts: `current_block_number > last_reward_block` is now `false`.
6. No rewards are credited to `S.unclaimed_rewards_own` or to any delegation pool for this block.
7. Repeat every block to permanently freeze all yield. [6](#0-5)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
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

**File:** src/staking/staking.cairo (L1398-1401)
```text
            self.general_prerequisites();
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
