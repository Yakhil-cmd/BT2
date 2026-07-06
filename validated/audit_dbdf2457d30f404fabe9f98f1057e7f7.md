### Title
Missing Access Control on `update_rewards` Allows Anyone to Permanently Freeze Staker Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` has no access control and accepts an attacker-controlled `disable_rewards` boolean. Any caller can invoke it with `disable_rewards: true`, which updates the global `last_reward_block` storage variable and returns early without distributing rewards. Because `last_reward_block` is a single global slot, this blocks every subsequent legitimate call for that block, allowing an attacker to permanently freeze all staker unclaimed yield by repeating the call each block.

### Finding Description
`IStakingRewardsManager::update_rewards` is a public, permissionless entry point:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
``` [1](#0-0) 

The function first asserts that the current block has not yet been processed:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

It then unconditionally writes the current block to the global `last_reward_block` slot, and only afterwards checks `disable_rewards`:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [3](#0-2) 

Because `last_reward_block` is a single, contract-wide storage slot (not keyed per staker), writing it with `disable_rewards: true` consumes the one allowed call for that block for **all** stakers. Any subsequent legitimate call — whether from the staker, a keeper, or the protocol — will revert with `REWARDS_ALREADY_UPDATED`.

The analog to the external report is direct: just as `TermMaxRouter::executeOperation()` performs a critical delegate-call before the whitelist check that lives inside `_doSwap()`, `update_rewards` performs the critical `last_reward_block.write` before any check on whether the caller is authorized to suppress rewards. The attacker-controlled parameter (`disable_rewards`) bypasses the reward-distribution logic while still consuming the per-block slot.

Attack path (no privileged role required):
1. Attacker monitors the mempool or simply calls `update_rewards(any_active_staker, disable_rewards: true)` at the start of every block.
2. `last_reward_block` is stamped with the current block number.
3. All legitimate `update_rewards` calls for that block revert with `REWARDS_ALREADY_UPDATED`.
4. No staker receives consensus-era block rewards for that block.
5. Repeated every block → permanent, protocol-wide freeze of unclaimed yield.

The only precondition is that consensus rewards are active (`!is_pre_consensus()`) and that the attacker supplies any currently active staker address with non-zero balance — both trivially satisfied on a live network. [4](#0-3) 

### Impact Explanation
**High** — Permanent freezing of unclaimed yield. Once an attacker begins calling `update_rewards(_, disable_rewards: true)` each block, no staker or delegator can ever accumulate consensus-era rewards. The yield is not redirected; it is simply never minted into the unclaimed-rewards accounting, constituting a permanent loss of yield for every participant in the protocol.

### Likelihood Explanation
**High** — The function is callable by any address with zero privilege requirements. The only input constraint is a valid, active staker address, which is publicly observable on-chain. Gas cost is the sole barrier, and on Starknet L2 that cost is negligible relative to the protocol-wide damage inflicted.

### Recommendation
Add an access-control guard to `update_rewards` so that only an authorized role (e.g., `only_app_governor` or a dedicated rewards-manager role) may invoke it with `disable_rewards: true`. Alternatively, split the function: keep a permissionless variant that always distributes rewards, and gate the `disable_rewards` path behind a privileged role. The `last_reward_block` write must not occur before the caller's authorization to suppress rewards has been verified.

### Proof of Concept
```
// Attacker script — run once per block while consensus rewards are active
loop {
    staking.update_rewards(
        staker_address = any_active_staker,  // publicly readable
        disable_rewards = true,
    );
    // last_reward_block is now stamped; all legitimate calls revert
    wait_for_next_block();
}
```

1. Attacker calls `update_rewards(active_staker, true)` at block N.
2. `last_reward_block` is written to N; function returns without distributing rewards.
3. Any legitimate call at block N reverts: `REWARDS_ALREADY_UPDATED`.
4. Repeated at block N+1, N+2, … → zero rewards ever distributed.
5. All staker and delegator `unclaimed_rewards_own` balances remain permanently at zero. [3](#0-2)

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
