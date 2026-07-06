### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze All Staker Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `src/staking/staking.cairo` is specified to be callable only by the Starkware sequencer, but the implementation contains no such access control check. Any unprivileged caller can invoke `update_rewards(staker_address, disable_rewards: true)` once per block to consume the global `last_reward_block` slot without distributing any rewards, permanently blocking the legitimate sequencer from distributing consensus rewards to all stakers for that block.

---

### Finding Description

The spec for `update_rewards` explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation only calls `general_prerequisites()`, which exclusively checks that the contract is not paused and that the caller is not the zero address: [2](#0-1) 

The `update_rewards` implementation: [3](#0-2) 

The critical state mutation is:

```
self.last_reward_block.write(current_block_number);
```

`last_reward_block` is a **single global** `BlockNumber` field (not per-staker): [4](#0-3) 

The guard at the top of `update_rewards` enforces that only one call per block can succeed across **all stakers**: [5](#0-4) 

When `disable_rewards: true` is passed, the function writes `last_reward_block` and returns immediately without distributing any rewards: [6](#0-5) 

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_staker_address, disable_rewards: true)` once per block. This:

1. Passes all checks (contract not paused, caller not zero, staker exists and is active, block is new).
2. Writes `last_reward_block = current_block_number`.
3. Returns without distributing any rewards.

Because `last_reward_block` is global, the legitimate sequencer's subsequent call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`. No staker receives consensus block rewards for that block. Repeated every block, this **permanently freezes all unclaimed consensus yield** for every staker in the protocol.

**Impact: High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

The attack requires no special role, no capital, and no setup beyond knowing any active staker address (which is publicly observable on-chain via `NewStaker` events). The cost is one transaction per block. The attack is trivially automatable and economically rational for a competitor or griever. Likelihood is **High**.

---

### Recommendation

Add a sequencer-only access control check at the top of `update_rewards`, consistent with the spec. The `RolesComponent` already present in the staking contract should expose a suitable role check (e.g., `only_sequencer` or equivalent). The check should be placed before any state mutation:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer(); // <-- add this
    self.general_prerequisites();
    ...
}
```

Alternatively, if the sequencer role is not yet defined, restrict callers to the attestation contract address (already stored in `attestation_contract` storage) or introduce a dedicated `sequencer` role in `RolesComponent`. [7](#0-6) 

---

### Proof of Concept

1. Deploy the system with consensus rewards active (`consensus_rewards_first_epoch` set and passed).
2. Observe that `staker_A` is a valid, active staker with non-zero balance.
3. In every new block, call from any EOA:
   ```
   IStakingRewardsManager(staking_contract).update_rewards(staker_A, disable_rewards: true)
   ```
4. The call succeeds (no role check), sets `last_reward_block = block_number`, and returns without distributing rewards.
5. The sequencer's call to `update_rewards(staker_A, disable_rewards: false)` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeat every block. All stakers accumulate zero consensus rewards indefinitely.

This is confirmed by the existing test suite, which demonstrates that `update_rewards` with `disable_rewards: true` succeeds from an arbitrary caller and produces zero rewards: [8](#0-7) [2](#0-1)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L141-142)
```text
        /// The contract that staker sends attestation transaction to.
        attestation_contract: ContractAddress,
```

**File:** src/staking/staking.cairo (L187-187)
```text
        last_reward_block: BlockNumber,
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
