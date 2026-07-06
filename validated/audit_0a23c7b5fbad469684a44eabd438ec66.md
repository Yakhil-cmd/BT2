Based on my investigation of the production code, this is a **real vulnerability**.

---

### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Suppress Block Rewards — (`src/staking/staking.cairo`)

### Summary

`update_rewards` is documented as restricted to "Only starkware sequencer" but the implementation enforces no such check. Any non-zero address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block and permanently discarding that block's rewards for all stakers.

### Finding Description

The spec at `docs/spec.md:1645` states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo:1449` is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // <-- only check
    ...
```

`general_prerequisites` (lines 1794–1797) only verifies the contract is unpaused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

There is no role check, no `assert_caller_is_sequencer`, and no allowlist. The function then unconditionally writes the current block number to the **global** `last_reward_block`:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [2](#0-1) 

The guard at lines 1454–1458 is also global — one successful call per block locks out all subsequent calls:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

### Impact Explanation

An attacker calls `update_rewards(any_valid_active_staker, disable_rewards: true)` once per block. Each call:
1. Passes all checks (non-zero caller, staker exists and is active, block is new).
2. Writes `last_reward_block = current_block`.
3. Returns early — **zero rewards distributed**.
4. Blocks every subsequent `update_rewards` call in that block with `REWARDS_ALREADY_UPDATED`.

Repeated every block, this permanently freezes all consensus block rewards for all stakers. The rewards are never minted/distributed; they are simply never attributed. This matches **High: Permanent freezing of unclaimed yield**. [4](#0-3) 

### Likelihood Explanation

The attack requires only a non-zero address and knowledge of any active staker address (which is public on-chain). It costs only gas per block. There is no economic barrier, no privileged role needed, and no race condition to win — the attacker simply needs to be first in each block, which is trivially achievable by front-running or by submitting at the start of each block.

### Recommendation

Add an access control check at the top of `update_rewards` that restricts the caller to the authorized sequencer address (or a designated role). For example:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
}
```

Alternatively, use the existing roles framework already present in the contract (e.g., `assert_only_operator` or a dedicated `SEQUENCER` role).

### Proof of Concept

1. Deploy the staking system with two active stakers, `staker_A` and `staker_B`, both past the K-epoch activation window with consensus rewards enabled.
2. From an arbitrary attacker address (any non-zero address), call:
   ```
   update_rewards(staker_address: staker_A, disable_rewards: true)
   ```
3. Observe: `last_reward_block` is now set to the current block; no rewards are distributed.
4. The legitimate sequencer now attempts:
   ```
   update_rewards(staker_address: staker_B, disable_rewards: false)
   ```
5. Observe: transaction reverts with `REWARDS_ALREADY_UPDATED`.
6. Advance one block and repeat from step 2 indefinitely.
7. After N blocks, both `staker_A` and `staker_B` have zero `unclaimed_rewards_own` despite N blocks of eligible consensus participation. The test at `src/flow_test/test.cairo:2882–2895` already demonstrates that `disable_rewards: true` produces zero rewards — the missing piece is that the access control gap lets an attacker be the one to set it. [5](#0-4)

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

**File:** src/staking/staking.cairo (L1794-1797)
```text
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/flow_test/test.cairo (L2882-2895)
```text
    // Disable rewards = true with consensus on - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: true);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
    advance_blocks(blocks: 1, block_duration: AVG_BLOCK_DURATION);
```
