### Title
Unprivileged caller can permanently freeze staker yield by front-running `update_rewards` with `disable_rewards: true` — (File: src/staking/staking.cairo)

---

### Summary

`update_rewards` in the Staking contract is documented as "Only starkware sequencer" but has **no caller access-control check** in the implementation. Any address can call it with `disable_rewards: true`, which advances the global `last_reward_block` sentinel without distributing any rewards. Because the sentinel is global and enforces exactly one call per block, a subsequent legitimate call by the sequencer in the same block reverts with `REWARDS_ALREADY_UPDATED`. An attacker who front-runs the sequencer every block permanently freezes unclaimed yield for all stakers.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is the sole mechanism for distributing per-block consensus rewards to stakers and their delegation pools. The spec explicitly restricts it to the Starkware sequencer, but the on-chain implementation only calls `general_prerequisites()`, which checks the pause flag and nothing else. [1](#0-0) 

The function then writes the current block number into the **global** `last_reward_block` storage slot before the `disable_rewards` branch: [2](#0-1) 

Because `last_reward_block` is a single (non-per-staker) value, one successful call per block — regardless of who made it or what `disable_rewards` was — exhausts the quota for every staker in that block. The spec confirms the intended single-caller model: [3](#0-2) 

The interface exposes this to any caller: [4](#0-3) 

---

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` before the sequencer in every block:

1. Passes all validation (staker exists, is active, has non-zero balance — all public on-chain data).
2. Writes `last_reward_block = current_block`.
3. Returns early — **zero rewards distributed**.
4. The sequencer's call in the same block hits `REWARDS_ALREADY_UPDATED` and reverts.

Repeated across every block, this **permanently freezes all unclaimed yield** for every staker and delegator in the protocol. Rewards are never credited to `unclaimed_rewards_own` and never forwarded to delegation pools.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- The attacker needs only a valid, active staker address — trivially obtained from on-chain events (`NewStaker`).
- No stake, no special role, and no token approval is required; only gas.
- On Starknet today the sequencer controls ordering, which raises the bar for front-running. However, the function is unconditionally public, so any window where the attacker's transaction is included first (e.g., during sequencer restarts, network congestion, or future decentralisation) is sufficient.
- The attack is cheap to sustain: one low-cost call per block.

Likelihood: **Medium** (constrained by sequencer ordering today; structurally trivial otherwise).

---

### Recommendation

Add an explicit caller check at the top of `update_rewards`, restricting it to the authorised sequencer address (or a role-based equivalent), consistent with the spec's stated access control:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.authorized_sequencer.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
}
```

---

### Proof of Concept

```
Block N:
  Eve  → update_rewards(alice_staker, disable_rewards: true)
         ✓ passes all checks, sets last_reward_block = N, returns (no rewards)
  Seq  → update_rewards(alice_staker, disable_rewards: false)
         ✗ REWARDS_ALREADY_UPDATED (N > N is false)

Block N+1:
  Eve  → update_rewards(alice_staker, disable_rewards: true)   [repeat]
  Seq  → REWARDS_ALREADY_UPDATED

... indefinitely: Alice and all other stakers accumulate zero rewards.
```

Relevant code path: [5](#0-4)

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

**File:** docs/spec.md (L1626-1646)
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
