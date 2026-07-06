### Title
Unvalidated `disable_rewards` Parameter in `update_rewards` Allows Permanent Freezing of Block Rewards - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` accepts a caller-controlled `disable_rewards` boolean with no access-control check. Because the function unconditionally advances the global `last_reward_block` cursor **before** inspecting `disable_rewards`, any unprivileged caller can permanently suppress reward distribution for the current block for every staker in the protocol.

### Finding Description

`update_rewards` is the sole entry point for distributing per-block consensus rewards to stakers. Its implementation in `src/staking/staking.cairo` follows this sequence:

1. Check `current_block_number > last_reward_block` (line 1454–1458).
2. Validate that `staker_address` is active and has non-zero balance (lines 1466–1482).
3. **Unconditionally write `last_reward_block = current_block_number`** (line 1485).
4. If `disable_rewards || self.is_pre_consensus()` → return early, distributing nothing (lines 1487–1489).
5. Otherwise, calculate and distribute block rewards (lines 1492–1506). [1](#0-0) 

The only access guard is `general_prerequisites()`, which merely asserts the contract is not paused and the caller is non-zero: [2](#0-1) 

`last_reward_block` is a single global storage slot (not per-staker): [3](#0-2) 

Because step 3 runs before step 4, calling `update_rewards(any_valid_staker, disable_rewards: true)` atomically:
- Marks the block as "already processed" in `last_reward_block`.
- Distributes zero rewards.
- Prevents any subsequent call to `update_rewards` for the same block (the assertion at step 1 will revert for every future caller).

The `disable_rewards` parameter is declared in the public interface with no restriction on who may set it: [4](#0-3) 

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, true)` once per block permanently destroys the block reward for **all** stakers and delegators in the protocol for that block. Because `last_reward_block` is global, the loss is irreversible: no retry is possible. Repeated across every block, this constitutes a complete, permanent freeze of all consensus-based unclaimed yield — matching the allowed impact "Permanent freezing of unclaimed yield."

### Likelihood Explanation

The function is permissionlessly callable by any non-zero address. No tokens, stake, or special role are required. The attacker only needs to supply any currently-active `staker_address` (readable from public events or view functions) and set `disable_rewards = true`. The cost is a single transaction per block. The attack is trivially automatable and has no economic barrier.

### Recommendation

Restrict who may call `update_rewards` with `disable_rewards = true`. Two complementary fixes:

1. **Move the `last_reward_block` write after the `disable_rewards` guard**, so that a call with `disable_rewards = true` does not consume the block slot:

```cairo
// Update last block rewards only when actually distributing.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number); // moved here
```

2. **Add role-based access control** so that only a trusted caller (e.g., the consensus layer or a designated rewards manager role) may invoke `update_rewards` with `disable_rewards = true`, analogous to how `pause` is restricted to `only_security_agent`: [5](#0-4) 

### Proof of Concept

```
// Attacker (any address) calls once per block:
staking.update_rewards(
    staker_address = <any active staker>,
    disable_rewards = true
);
// last_reward_block is now set to current_block_number.
// No rewards distributed.
// Any subsequent call by the legitimate staker reverts with REWARDS_ALREADY_UPDATED.
// Block rewards are permanently lost for all stakers.
```

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1250-1257)
```text
        fn pause(ref self: ContractState) {
            self.roles.only_security_agent();
            if self.is_paused() {
                return;
            }
            self.is_paused.write(true);
            self.emit(PauseEvents::Paused { account: get_caller_address() });
        }
```

**File:** src/staking/staking.cairo (L1449-1489)
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
