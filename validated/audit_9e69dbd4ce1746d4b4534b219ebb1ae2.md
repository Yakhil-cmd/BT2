### Title
Unprivileged Caller Can Permanently Freeze Consensus Block Rewards via `update_rewards` Early-Return After State Mutation - (File: src/staking/staking.cairo)

### Summary
`update_rewards` in `staking.cairo` writes `last_reward_block` to storage **before** checking the `disable_rewards` flag. Because `disable_rewards` is a caller-controlled parameter with no access control, any unprivileged address can call `update_rewards(staker_address, disable_rewards: true)` to mark a block as "processed" without distributing any rewards. The block's rewards are permanently lost.

### Finding Description

`update_rewards` is a public function gated only by `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero. [1](#0-0) 

Inside `update_rewards`, the function first validates the staker, then **unconditionally writes** `last_reward_block` to the current block number: [2](#0-1) 

Only **after** this state mutation does it check whether to actually distribute rewards:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← state mutated

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← early return, no rewards distributed
}
``` [2](#0-1) 

The guard at the top of the function prevents any future call for the same block:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

`last_reward_block` is a **single global value** shared across all stakers: [4](#0-3) 

### Impact Explanation

For every block N an attacker front-runs with `update_rewards(any_staker, disable_rewards: true)`:

1. `last_reward_block` is set to N.
2. No rewards are distributed.
3. Any subsequent legitimate call for block N fails with `REWARDS_ALREADY_UPDATED`.
4. The consensus block rewards for block N are **permanently lost** — they can never be reclaimed because the per-block reward window is closed.

Because `last_reward_block` is global, a single front-run call prevents **all stakers** from receiving rewards for that block. Repeated across every block, this permanently freezes all consensus (V3) block rewards.

**Impact: High — Permanent freezing of unclaimed yield.**

### Likelihood Explanation

- No privileged role is required; `general_prerequisites()` only checks pause state and non-zero caller.
- The attacker pays only gas. The attack is profitable for a competing validator who wants to suppress rivals' rewards.
- Front-running a single public transaction per block is straightforward on Starknet.

### Recommendation

Move the `last_reward_block.write` **after** the `disable_rewards` / `is_pre_consensus` guard, so the block is only marked as processed when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);

let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
...
``` [5](#0-4) 

### Proof of Concept

1. Staker Alice is active and eligible for consensus block rewards at block N.
2. Attacker Bob (any address) calls `update_rewards(alice_address, disable_rewards: true)` at block N.
3. `last_reward_block` is written to N; function returns early with no rewards sent.
4. The legitimate sequencer/relayer calls `update_rewards(alice_address, disable_rewards: false)` at block N — it reverts with `REWARDS_ALREADY_UPDATED`.
5. Alice's block-N rewards are permanently lost.
6. Bob repeats this for every block, freezing all consensus rewards indefinitely. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
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
