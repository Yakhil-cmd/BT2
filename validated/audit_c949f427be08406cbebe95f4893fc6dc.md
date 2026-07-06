### Title
Unrestricted `update_rewards` Allows Any Staker to Monopolize All Consensus Block Rewards - (File: src/staking/staking.cairo)

### Summary
In the consensus rewards phase, `update_rewards` is a public function with no caller access control. A single staker can call it for themselves on every block, consuming the global `last_reward_block` slot and receiving 100% of each block's reward allocation. All other stakers are permanently excluded from consensus rewards.

### Finding Description
`update_rewards` in `StakingRewardsManagerImpl` is callable by any non-zero address with no role restriction. Its only replay guard is a **global** `last_reward_block` variable: only one call per block succeeds. [1](#0-0) 

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
``` [2](#0-1) 

After the guard passes, `last_reward_block` is immediately written to the current block number, locking out every other caller for that block:

```cairo
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
// ... distributes full block rewards to `staker_address`
``` [3](#0-2) 

When `disable_rewards=false` and the system is in the consensus phase, `_update_rewards` is called with `strk_total_stake = staker_total_strk_balance` (the **calling staker's own total balance**, not the global total stake): [4](#0-3) 

Inside `calculate_staker_own_rewards`, the formula is:

```
staker_own_rewards = block_rewards * own_balance / staker_total_balance
``` [5](#0-4) 

Because `strk_total_stake` is the staker's own total (not the protocol-wide total), the staker receives the **entire block reward** for that block (split only between their own stake and their pool, if any). No other staker receives anything for that block.

There is no per-staker epoch or block counter, no whitelist, and no privileged-caller check on `update_rewards`. [6](#0-5) 

### Impact Explanation
A staker who calls `update_rewards(self, false)` on every block:

1. Consumes the single global `last_reward_block` slot each block.
2. Receives 100% of each block's STRK (and BTC) reward allocation.
3. Causes every other staker to receive **zero** consensus rewards indefinitely.

This constitutes **theft of unclaimed yield** from all other stakers — a High-severity impact under the allowed scope.

### Likelihood Explanation
- The function is fully public; any registered staker can call it.
- The attacker needs only to submit a transaction before the legitimate consensus caller each block — a straightforward front-run on a public mempool.
- The cost is only gas; there is no stake requirement beyond the existing `min_stake` to become a staker.
- The attack is sustainable indefinitely as long as the attacker remains a staker.

### Recommendation
Restrict `update_rewards` to a trusted caller (e.g., a designated consensus contract address stored in storage, similar to how `update_rewards_from_attestation_contract` restricts to `attestation_contract`):

```cairo
fn update_rewards(...) {
    self.assert_caller_is_consensus_contract(); // add this guard
    ...
}
```

Alternatively, introduce a per-staker block/epoch reward counter so that a staker cannot receive rewards more than once per epoch regardless of who calls the function.

### Proof of Concept

1. Attacker deploys or controls a staker account `A` with `min_stake` STRK.
2. Attacker monitors the mempool / block production.
3. At the start of every new block (or via a bot), attacker calls:
   ```
   staking.update_rewards(staker_address=A, disable_rewards=false)
   ```
4. Because `last_reward_block` is global and the attacker is first, the call succeeds and `A` receives the full block reward via `_update_rewards`.
5. Any subsequent call by another staker or the consensus mechanism in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeated every block, attacker accumulates all consensus rewards; all other stakers accumulate zero. [7](#0-6)

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
