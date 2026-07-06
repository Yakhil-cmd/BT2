### Title
Any Caller Can Invoke `update_rewards` with `disable_rewards: true` to Permanently Suppress Block Reward Distribution — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract has no caller authentication. Any unprivileged address can call it with `disable_rewards: true`, which atomically marks the current block as "rewards already updated" while skipping actual reward distribution. Because `last_reward_block` is a single global slot, one such call per block permanently forfeits that block's rewards for every staker and delegator in the protocol.

---

### Finding Description

`update_rewards` is exposed as a public ABI function under `IStakingRewardsManager`. Its only guard is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero — no role, no ownership, no identity check. [1](#0-0) 

The function accepts a caller-controlled `disable_rewards: bool` parameter. When `true`, execution proceeds as follows:

1. The assertion at lines 1453–1458 enforces **one call per block** using the global `last_reward_block` storage variable.
2. `last_reward_block` is unconditionally written to `current_block_number` at line 1485 — **before** the early-return guard.
3. The early-return at lines 1487–1489 exits without distributing any rewards. [2](#0-1) 

`last_reward_block` is a single global slot (not per-staker): [3](#0-2) 

Because the slot is consumed before the early return, any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`. The rewards for that block are permanently unrecoverable.

The analog to the NFT report is direct: just as the `CraftingSystem` did not verify that the caller owned the NFT before locking it (allowing any user to consume a locked NFT's reservation), `update_rewards` does not verify that the caller is the staker (or any authorized party) before consuming the block's reward slot — allowing any user to burn that slot with zero rewards distributed.

---

### Impact Explanation

In the consensus-rewards phase (`consensus_rewards_first_epoch` is set and `current_epoch >= consensus_rewards_first_epoch`), block rewards are distributed exactly once per block through `update_rewards`. An attacker who calls `update_rewards(any_valid_staker, true)` first in a block causes:

- `last_reward_block` to advance to the current block with no rewards minted or credited.
- All stakers' `unclaimed_rewards_own` and all delegation-pool reward traces to receive **zero** for that block.
- No recovery path: the block number cannot be reused.

Repeated across blocks, this constitutes **permanent freezing of unclaimed yield** for all stakers and delegators — matching the High-impact category in the allowed scope. [4](#0-3) 

---

### Likelihood Explanation

- **No privilege required**: any non-zero address suffices.
- **Minimal precondition**: the attacker only needs to supply any currently active staker address with non-zero STRK balance, which is trivially discoverable from on-chain events (`NewStaker`).
- **Cost**: gas only; the call does not transfer any tokens.
- **Automation**: a bot can front-run every block's first `update_rewards` call with `disable_rewards: true`.

Likelihood is **High**.

---

### Recommendation

Add an access-control check so that only the staker themselves, their registered operational address, or a designated privileged role can invoke `update_rewards`. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    let caller = get_caller_address();
    let staker_info = self.internal_staker_info(:staker_address);
    assert!(
        caller == staker_address || caller == staker_info.operational_address,
        "{}",
        Error::CALLER_CANNOT_UPDATE_REWARDS,
    );
    // ... rest of function
}
```

Alternatively, remove `disable_rewards` from the public interface entirely and handle reward suppression through a separate privileged governance function.

---

### Proof of Concept

1. Protocol enters consensus-rewards phase (`current_epoch >= consensus_rewards_first_epoch`).
2. Attacker identifies any valid, active staker address `S` (e.g., from a `NewStaker` event).
3. At the start of block `B`, attacker submits:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. Inside the call:
   - `current_block_number (B) > last_reward_block` → assertion passes.
   - `last_reward_block` is written to `B`.
   - `disable_rewards == true` → early return; `_update_rewards` is never called.
5. The legitimate staker (or anyone else) calls `update_rewards(S, false)` later in block `B`:
   - `current_block_number (B) > last_reward_block (B)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
6. Block `B`'s rewards are permanently lost for all stakers and delegators.
7. Repeating steps 3–6 every block suppresses all consensus-phase reward distribution indefinitely. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1507)
```text
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
```
