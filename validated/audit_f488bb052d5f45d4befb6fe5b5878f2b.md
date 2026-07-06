### Title
Missing Access Control on `update_rewards` Allows Any Staker to Steal All Block Rewards - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in `Staking.cairo` is documented in the spec as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Combined with a single global `last_reward_block` guard that allows only one staker to receive rewards per block, any staker can front-run the sequencer every block, claim 100% of block rewards for themselves, and permanently deny all other stakers their yield for those blocks.

### Finding Description

`IStakingRewardsManager::update_rewards` is the V3 consensus-rewards entry point. Its spec explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation only calls `general_prerequisites()`, which checks two things: the contract is not paused, and the caller is not the zero address. [1](#0-0) 

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only: not-paused + caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
``` [2](#0-1) 

There is no role check — no `only_sequencer`, no `only_operator`, nothing. Any non-zero address may call this function.

The global `last_reward_block` field is a single value shared across all stakers: [3](#0-2) 

After the first successful call in a block, `last_reward_block` is written to the current block number: [4](#0-3) 

Every subsequent call in the same block — including the legitimate sequencer call for any other staker — reverts with `REWARDS_ALREADY_UPDATED`.

In V3 consensus rewards, the reward calculation passes the **calling staker's own total balance** as `strk_total_stake`, not the protocol-wide total stake: [5](#0-4) 

Inside `_update_rewards`, the staker's own rewards are:

```
staker_own_rewards = block_rewards * own_balance / staker_total_balance
``` [6](#0-5) 

Because `staker_total_balance = own_balance + delegated_balance`, the staker and their pool together receive **100% of the block rewards** for that block. No other staker receives anything.

### Impact Explanation

An attacker who is a registered staker calls `update_rewards(attacker_address, false)` at the start of every block. Because there is no access control:

1. The attacker receives 100% of every block's STRK (and BTC) rewards, regardless of their proportional share of total stake.
2. `last_reward_block` is set to the current block, causing every subsequent call in that block to revert.
3. All other stakers receive **zero rewards** for every block the attacker front-runs.

This constitutes **theft of unclaimed yield** (High impact) and **permanent freezing of unclaimed yield** for all other stakers on every affected block.

### Likelihood Explanation

- The attacker only needs to be a registered staker (meet `min_stake`).
- The attack is a simple, unconditional call — no flash loan, no complex setup.
- The attack is economically profitable whenever the attacker's proportional share of total stake is less than 100% (i.e., always, in a multi-staker system).
- The attack is sustainable indefinitely; there is no self-correcting mechanism.

### Recommendation

Add the sequencer-only access control that the spec requires. Introduce a role (e.g., `SEQUENCER_ROLE` or reuse an existing operator role) and assert it at the top of `update_rewards`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer();   // <-- add this
    self.general_prerequisites();
    ...
}
```

Alternatively, if the sequencer address is known at deployment, store it and assert `get_caller_address() == sequencer_address`.

### Proof of Concept

```
Setup:
  - Attacker stakes min_stake (e.g., 20,000 STRK).
  - 100 other stakers each stake 1,000,000 STRK.
  - Consensus rewards are active.

Attack loop (every block):
  1. Attacker calls staking.update_rewards(attacker_address, false).
     - No access control check fires.
     - block_rewards (e.g., 1000 STRK) are computed.
     - Attacker receives 1000 STRK (100% of block rewards).
     - last_reward_block = current_block.
  2. Sequencer (or any other party) attempts update_rewards(other_staker, false).
     - Reverts: REWARDS_ALREADY_UPDATED.
  3. All 100 legitimate stakers receive 0 STRK for this block.

Result:
  - Attacker drains the reward supplier of all consensus block rewards.
  - All other stakers' unclaimed yield is permanently lost for every
    block the attacker front-runs.
``` [7](#0-6)

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

**File:** src/staking/staking.cairo (L1905-1924)
```text
        fn calculate_staker_own_rewards(
            self: @ContractState,
            staker_address: ContractAddress,
            strk_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            curr_epoch: Epoch,
        ) -> Amount {
            let own_balance_curr_epoch = self
                .get_staker_own_balance_at_epoch(:staker_address, epoch_id: curr_epoch);
            // In V3 (consensus rewards), this error is unreachable since `update_rewards` is not
            // valid for stakers without balance.
            assert!(own_balance_curr_epoch.is_non_zero(), "{}", Error::ATTEST_WITH_ZERO_BALANCE);

            mul_wide_and_div(
                lhs: strk_total_rewards,
                rhs: own_balance_curr_epoch.to_strk_native_amount(),
                div: strk_total_stake.to_strk_native_amount(),
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
        }
```
