### Title
Missing Access Control on `update_rewards` Allows Any Caller to Front-Run Block Reward Distribution — (`src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is documented as callable only by the "starkware sequencer," but the implementation enforces no such restriction. Any non-zero address can call it. Combined with a **global** (not per-staker) `last_reward_block` guard, an attacker can front-run the legitimate sequencer every block, choosing which staker receives block rewards and denying all other stakers their rewards for that block.

---

### Finding Description

The `general_prerequisites` function — the only prerequisite called by `update_rewards` — checks only pause state and non-zero caller: [1](#0-0) 

There is no role check, no sequencer check, and no `get_caller_address()` comparison anywhere in `update_rewards`: [2](#0-1) 

The replay guard is a **single global** `last_reward_block` storage variable — not per-staker: [3](#0-2) 

This means: once any caller sets `last_reward_block = N`, no other call can succeed at block `N`. The guard is per-block, not per-epoch, so the attacker can call it once per block across an entire epoch.

The spec explicitly states access control is "Only starkware sequencer": [4](#0-3) 

---

### Impact Explanation

Each successful call (once per block) triggers cross-contract calls to the reward supplier: [5](#0-4) 

Specifically, `calculate_block_rewards` calls `reward_supplier.update_current_epoch_block_rewards()`, and `_update_rewards` calls `reward_supplier.update_unclaimed_rewards_from_staking_contract()` and `claim_from_reward_supplier`: [6](#0-5) 

An attacker who front-runs the sequencer at every block:
1. Chooses which staker receives block rewards for that block (e.g., their own staker).
2. Causes the sequencer's legitimate call for the intended staker to revert with `REWARDS_ALREADY_UPDATED`.
3. Permanently denies other stakers their per-block rewards for every block the attacker front-runs.
4. Forces repeated unnecessary cross-contract calls to the reward supplier, wasting gas.

This constitutes **theft/permanent freezing of unclaimed yield** for non-attacker stakers (High), and at minimum **griefing with unbounded gas consumption** (Medium).

---

### Likelihood Explanation

The attack requires no privilege, no special setup, and no capital beyond gas. Any EOA or contract can call `update_rewards` with any `staker_address`. On Starknet, front-running is feasible via mempool observation or by simply submitting the call at the start of each block. The vulnerability is trivially exploitable.

---

### Recommendation

Add a sequencer/role check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` checks `CALLER_IS_NOT_ATTESTATION_CONTRACT`. For example:

```rust
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
```

Alternatively, use the existing roles framework to gate this function to a `REWARDS_MANAGER` role held by the sequencer address.

---

### Proof of Concept

```
// Block N:
// Attacker (any address) calls:
staking_rewards_dispatcher.update_rewards(attacker_staker_address, disable_rewards: false);
// → last_reward_block = N, attacker's staker gets block rewards
// → reward_supplier.update_current_epoch_block_rewards() called
// → reward_supplier.update_unclaimed_rewards_from_staking_contract() called

// Sequencer then tries (same block N):
staking_rewards_dispatcher.update_rewards(legitimate_staker_address, disable_rewards: false);
// → PANICS: REWARDS_ALREADY_UPDATED (current_block_number N is NOT > last_reward_block N)

// Repeat for every block in the epoch.
// Result: attacker's staker accumulates all block rewards; all other stakers receive zero.
```

The invariant "reward supplier is called at most once per epoch per staker" is not violated — but the invariant "only the authorized sequencer decides which staker gets rewards per block" is completely broken due to the missing access control. [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L1447-1508)
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
    }
```

**File:** src/staking/staking.cairo (L1794-1797)
```text
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2351-2360)
```text
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
```

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
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
