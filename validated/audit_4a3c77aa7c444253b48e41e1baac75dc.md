### Title
Missing Caller Validation on `update_rewards` Allows Any Address to Permanently Deny Block Rewards to All Stakers - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` to consume the per-block reward slot, permanently preventing the sequencer from distributing consensus-era block rewards for that block.

### Finding Description
The spec explicitly states the access control for `update_rewards`:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation in `StakingRewardsManagerImpl` performs no `get_caller_address()` check whatsoever:

```cairo
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
    ...
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;
    }
    // ... distribute rewards
``` [2](#0-1) 

The `last_reward_block` is a single global storage variable. Once it is set to the current block number, the `REWARDS_ALREADY_UPDATED` assertion prevents any further `update_rewards` call in the same block: [3](#0-2) 

An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)`. This:
1. Passes all checks (staker exists, has non-zero balance, block is new).
2. Writes `last_reward_block = current_block_number`.
3. Returns early without distributing rewards (because `disable_rewards == true`).

The sequencer's subsequent call with `disable_rewards: false` for any staker in the same block will revert with `REWARDS_ALREADY_UPDATED`. The block rewards are permanently lost — they are never credited to `unclaimed_rewards_own` or transferred to pools.

This is the direct analog to the Docker "running as root" class: a privileged operation (reward distribution) has no privilege check, so any unprivileged caller can exercise it with destructive parameters.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Every block in the consensus-rewards era, the sequencer is expected to call `update_rewards` with `disable_rewards: false` to credit stakers and their delegation pools with block rewards. An attacker who front-runs this call with `disable_rewards: true` causes the entire block's reward allocation to be silently skipped. Because `last_reward_block` is already set, the sequencer's call reverts and the rewards for that block are never minted or credited. Repeated every block, this permanently denies all consensus-era rewards to all stakers and delegators.

### Likelihood Explanation
**High.** The function is public, requires no special role, and the attack costs only gas. It can be automated with a simple bot that monitors the mempool or block production and submits a `update_rewards(..., disable_rewards: true)` transaction each block. There is no economic barrier.

### Recommendation
Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the configured sequencer address (or a dedicated operator role), consistent with the spec's stated access control:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
```

Alternatively, restrict it to an `OPERATOR` role already present in the RBAC system. [4](#0-3) 

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. A valid staker `S` exists with non-zero balance.
3. Attacker `A` (any address) calls `staking.update_rewards(S, disable_rewards: true)` at block `N`.
   - `last_reward_block` is written to `N`.
   - No rewards are distributed.
4. Sequencer calls `staking.update_rewards(S, disable_rewards: false)` at block `N`.
   - Reverts: `REWARDS_ALREADY_UPDATED` (because `N > N` is false).
5. Block `N` rewards are permanently lost for all stakers.
6. Repeat at block `N+1`, `N+2`, … to permanently deny all consensus rewards. [5](#0-4)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1447-1507)
```text
    #[abi(embed_v0)]
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
