### Title
Unrestricted `disable_rewards` Parameter in `update_rewards` Allows Permanent Freezing of Consensus Block Rewards - (File: src/staking/staking.cairo)

### Summary
`update_rewards` is a public function callable by any non-zero address. It accepts a `disable_rewards: bool` parameter with no access control. When called with `disable_rewards: true`, the function writes the current block number to the global `last_reward_block` storage slot and returns early — distributing zero rewards. Because `last_reward_block` is a protocol-wide lock, any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` first in every block permanently prevents all stakers and delegators from receiving consensus block rewards.

### Finding Description
`update_rewards` is defined in `StakingRewardsManagerImpl` and gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role check, no ownership check. [1](#0-0) 

The function writes `last_reward_block` to the current block **before** evaluating `disable_rewards`: [2](#0-1) 

Once `last_reward_block` equals the current block, the guard at the top of the function causes every other call in that block to revert: [3](#0-2) 

`last_reward_block` is a single global slot, not per-staker: [4](#0-3) 

The attacker only needs to supply any currently-active staker address with non-zero STRK balance to pass the two staker-validity assertions. Active stakers are publicly enumerable via `get_stakers`.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Consensus block rewards are computed per-block and distributed only when `update_rewards` is called with `disable_rewards: false`. If the attacker wins the race in every block, the rewards for those blocks are never computed or accumulated anywhere — they are permanently lost. All stakers and all delegators in every pool are affected simultaneously, because the lock is global.

### Likelihood Explanation
**Medium.** The attacker does not need to front-run a specific victim transaction; they simply need to submit `update_rewards(any_valid_staker, disable_rewards: true)` as the first transaction in each block. On Starknet the sequencer orders transactions, so a well-resourced attacker (or the sequencer itself acting maliciously) can reliably achieve this. Even without sequencer collusion, a bot that submits the call at the start of every block will succeed whenever no legitimate caller acts first, which is the common case (legitimate callers are not required to call every block).

### Recommendation
Restrict the `disable_rewards: true` path to a privileged role (e.g., `security_agent` or `app_governor`). The simplest fix is to add a role check before the early-return branch:

```cairo
if disable_rewards {
    self.roles.only_security_agent(); // or equivalent privileged role
    return;
}
```

Alternatively, remove `disable_rewards` from the public interface entirely and expose a separate privileged function for the "skip rewards" use-case.

### Proof of Concept
1. Attacker identifies any active staker `S` with non-zero STRK balance (readable from `get_stakers`).
2. At the start of each Starknet block, attacker submits:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. The function passes all assertions, writes `last_reward_block = current_block`, and returns without distributing rewards.
4. Any legitimate `update_rewards` call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeating this every block causes all consensus block rewards to be permanently lost for all stakers and delegators. [5](#0-4)

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
