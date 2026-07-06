### Title
Unprivileged Caller Can Permanently Freeze Block Rewards for All Stakers via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `src/staking/staking.cairo` is callable by any unprivileged actor. It writes the global `last_reward_block` storage variable **before** checking the `disable_rewards` flag. An attacker can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block to permanently prevent every staker from receiving block rewards for that block, with no profit motive required and no recovery path.

### Finding Description

`update_rewards` is part of `StakingRewardsManagerImpl` and has no access control beyond `general_prerequisites()`, which only checks that the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function flow is:

1. Assert `current_block_number > last_reward_block` (prevents double-claiming per block).
2. **Write** `last_reward_block = current_block_number` — this is the global, single-slot storage variable.
3. **Then** check `if disable_rewards || is_pre_consensus() { return; }` — skipping all reward distribution. [2](#0-1) 

Because `last_reward_block` is a single global `BlockNumber` (not a per-staker map), writing it before the `disable_rewards` guard means:

- Any caller who invokes `update_rewards(any_active_staker, disable_rewards: true)` at block N consumes the block's reward slot for **all** stakers.
- Any subsequent legitimate call at block N reverts with `REWARDS_ALREADY_UPDATED`.
- The rewards for block N are permanently unclaimable — there is no mechanism to retroactively distribute them. [3](#0-2) 

The global nature of `last_reward_block` is confirmed in the storage struct: [4](#0-3) 

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

A single transaction per block permanently destroys block rewards for every active staker. If executed continuously (e.g., via a bot), no staker ever receives consensus-era block rewards. The STRK that would have been minted and distributed is never claimed, constituting a permanent freeze of unclaimed yield at protocol scale.

### Likelihood Explanation

**High.** The function is public with no role check. The only prerequisite is supplying any currently-active staker address (trivially obtained from on-chain events or `get_stakers`). On Starknet, transaction fees are low enough that continuous griefing is economically viable. No leaked key, privileged role, or external dependency is required.

### Recommendation

Move `last_reward_block.write` to **after** the `disable_rewards` guard, so a no-op call does not consume the block's reward slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
// ... rest of reward distribution
```

Alternatively, restrict who may pass `disable_rewards: true` (e.g., only the staker themselves or a trusted attestation contract) via an explicit caller check.

### Proof of Concept

1. Staker A is active and eligible for block rewards at block N.
2. Attacker (any address) calls `update_rewards(staker_A_address, disable_rewards: true)` at block N.
   - `last_reward_block` is written to N.
   - Function returns early; no rewards distributed.
3. Staker A (or anyone) calls `update_rewards(staker_A_address, disable_rewards: false)` at block N.
   - Reverts: `REWARDS_ALREADY_UPDATED` (`current_block_number > last_reward_block` is false).
4. Staker A permanently loses block rewards for block N.
5. Repeated every block → staker A (and all other stakers, since `last_reward_block` is global) receive zero consensus rewards indefinitely.

**Golom analog mapping:**
- `disable_rewards: true` ↔ `o.totalAmt = 0` (zeroes the reward/fee calculation)
- `last_reward_block` write before the guard ↔ state update that prevents re-execution (the "hidden" side-effect that makes the bypass permanent)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1452)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1453-1489)
```text
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
```
