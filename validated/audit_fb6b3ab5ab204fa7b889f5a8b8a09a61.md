### Title
Global `last_reward_block` Updated When `disable_rewards: true` Enables Griefing of All Stakers' Block Rewards - (File: src/staking/staking.cairo)

### Summary
The public `update_rewards` function unconditionally writes `last_reward_block` to the current block number before checking the `disable_rewards` flag. Because there is no access control on `disable_rewards`, any unprivileged caller can invoke `update_rewards(any_valid_staker, disable_rewards: true)` each block, consuming the single per-block reward slot without distributing any rewards, permanently denying all stakers their consensus-period block rewards for those blocks.

### Finding Description
`update_rewards` enforces a global, per-block lock via `last_reward_block`:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

After validating the staker, it unconditionally commits the lock:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← lock consumed here

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← no rewards distributed
}
``` [1](#0-0) 

`last_reward_block` is a single global storage slot shared across all stakers. [2](#0-1) 

`update_rewards` is embedded as a public ABI entry point with no role guard — `general_prerequisites` only checks pause state and non-zero caller: [3](#0-2) [4](#0-3) 

The `disable_rewards` parameter is accepted from any caller with no restriction. Passing `true` causes the function to return immediately after writing `last_reward_block`, so no rewards flow to any staker or pool for that block. Because the slot is already consumed, every subsequent call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.

### Impact Explanation
In the consensus-rewards period, each block's STRK and BTC rewards are distributed to exactly one staker via `update_rewards`. When the attacker consumes the slot with `disable_rewards: true`, the rewards that would have been calculated by `_update_rewards` and credited to `unclaimed_rewards_own` / forwarded to pools are never generated. They cannot be retroactively recovered — the block is gone. Sustained over many blocks, this permanently destroys yield for all stakers and their delegators.

This matches **Medium: Griefing with no profit motive but damage to users or protocol**.

### Likelihood Explanation
The attack requires one cheap transaction per block. On Starknet, gas costs are low. The attacker does not need to be a staker; they only need to supply any currently-active staker address with non-zero balance (trivially readable on-chain). No privileged key, bridge access, or external dependency is needed. The attacker can also selectively front-run legitimate `update_rewards` calls to deny specific stakers rather than running continuously.

### Recommendation
Move the `last_reward_block` write to after the `disable_rewards` / `is_pre_consensus` guard, so the slot is only consumed when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Only consume the per-block slot when rewards are actually distributed.
self.last_reward_block.write(current_block_number);

let reward_supplier_dispatcher = ...;
```

Alternatively, restrict `disable_rewards: true` to a trusted role (e.g., `only_security_agent`), or remove the parameter entirely if no legitimate unprivileged use case exists.

### Proof of Concept
1. Consensus rewards are active (`consensus_rewards_first_epoch` has passed).
2. Attacker (any address) identifies any active staker `S` with non-zero STRK balance.
3. At the start of each block, attacker submits:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. `last_reward_block` is set to the current block number; no rewards are distributed.
5. Any legitimate staker who calls `update_rewards` in the same block receives `REWARDS_ALREADY_UPDATED` and reverts.
6. The block's STRK/BTC rewards are permanently lost — `unclaimed_rewards_own` for all stakers is never incremented, and no pool rewards are forwarded.
7. Repeating step 3 every block indefinitely denies all stakers their consensus block rewards.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1452)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1453-1490)
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
