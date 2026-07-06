### Title
Missing Caller Validation in `update_rewards` Allows Any Address to Permanently Freeze Block Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `IStakingRewardsManager` interface is documented as callable only by the Starkware sequencer, but the implementation contains no caller validation. Any unprivileged address can call it with `disable_rewards: true`, consuming the single per-block reward slot and permanently preventing reward distribution for that block across all stakers.

### Finding Description
The `update_rewards` function is the consensus-era reward distribution entry point. The spec explicitly states its access control is "Only starkware sequencer." [1](#0-0) 

However, the implementation performs no such check. The only guards are `general_prerequisites()` (unpaused + non-zero caller) and a block-deduplication check against `last_reward_block`: [2](#0-1) 

`last_reward_block` is a **single global storage slot** — not per-staker: [3](#0-2) 

Once `update_rewards` is called in a block (for any staker, with any `disable_rewards` value), `last_reward_block` is written to the current block number: [4](#0-3) 

Any subsequent call in the same block — including the sequencer's legitimate call — will revert with `REWARDS_ALREADY_UPDATED`. Because block numbers are monotonically increasing and the slot is consumed, the rewards for that block are **permanently unrecoverable**.

The analog to the snap vulnerability is exact: just as any dapp could call `onRpcRequest()` because origin was never validated, any address can call `update_rewards()` because the caller is never validated against the expected sequencer address.

### Impact Explanation
An attacker calling `update_rewards(any_valid_staker, disable_rewards: true)` at the start of any block:

1. Sets `last_reward_block` to the current block number.
2. Causes the sequencer's own `update_rewards` call (with `disable_rewards: false`) to revert with `REWARDS_ALREADY_UPDATED`.
3. No rewards are distributed for that block to any staker or pool.
4. The block's reward slot is permanently consumed — there is no recovery path.

This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators for every attacked block. The attacker can sustain this indefinitely at negligible cost (only gas).

**Impact category: High — Permanent freezing of unclaimed yield.**

### Likelihood Explanation
The function is publicly callable by any non-zero address with no economic barrier. The attacker only needs to submit a transaction before the sequencer's reward update transaction in each block. On Starknet, where transaction ordering within a block is sequencer-controlled, a griefing attacker can repeatedly submit this call at the start of each block. The attack is cheap, repeatable, and requires no special privileges or capital.

### Recommendation
Add an explicit caller check at the top of `update_rewards`, analogous to the pattern already used in `update_rewards_from_attestation_contract` and `update_current_epoch_block_rewards`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // Add this check
    ...
}
```

Store the authorized sequencer address in contract storage (set at construction or via a governance-controlled setter) and assert `get_caller_address() == self.sequencer_address.read()`. Alternatively, restrict via the existing roles system (e.g., a dedicated `SEQUENCER_ROLE`).

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has passed).
2. Staker `S` is active with non-zero balance.
3. Attacker `A` (any address) calls `update_rewards(S, disable_rewards: true)` at block `N`.
4. `last_reward_block` is written to `N`; no rewards are distributed.
5. Sequencer calls `update_rewards(S, disable_rewards: false)` in the same block `N`.
6. The call reverts: `current_block_number (N) > last_reward_block (N)` is false → `REWARDS_ALREADY_UPDATED`.
7. Staker `S` and all pool members receive zero rewards for block `N`.
8. Attacker repeats step 3 every block, permanently denying all consensus-era rewards. [5](#0-4)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

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
