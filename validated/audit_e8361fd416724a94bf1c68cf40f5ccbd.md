### Title
`update_rewards` Updates Global `last_reward_block` Before `disable_rewards` Guard, Enabling Permanent Griefing of All Staker Rewards - (File: src/staking/staking.cairo)

---

### Summary

`update_rewards` in `StakingRewardsManagerImpl` writes the global `last_reward_block` storage variable **before** checking the `disable_rewards` flag. Because `update_rewards` has no access-control guard (only `general_prerequisites`, which checks pause state and non-zero caller), any unprivileged address can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block. Each such call consumes the block's reward slot without distributing any rewards, permanently destroying that block's unclaimed yield for every staker in the protocol.

---

### Finding Description

`update_rewards` is a public function in `IStakingRewardsManager`:

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
    ...
    // Update last block rewards.          ← written unconditionally
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                            ← exits WITHOUT distributing rewards
    }
    // actual reward distribution follows
```

`last_reward_block` is a **single global** storage slot shared across all stakers. The one-call-per-block invariant is enforced by the `current_block_number > self.last_reward_block.read()` assertion at the top. Because the write happens before the `disable_rewards` branch, calling `update_rewards(valid_staker, disable_rewards: true)` at block N:

1. Passes all validity checks (staker exists, is active, has non-zero balance).
2. Writes `last_reward_block = N`.
3. Returns immediately — no rewards are distributed to anyone.
4. Every subsequent call to `update_rewards` at block N reverts with `REWARDS_ALREADY_UPDATED`.

The attacker can repeat this at every block, permanently preventing the entire protocol from distributing consensus-era block rewards.

The analog to the external report is exact: just as matching-pool donations bypass the round-activity check and consume state that should only be consumed under valid conditions, `update_rewards` with `disable_rewards = true` consumes the global `last_reward_block` slot — a state update that should only occur when rewards are actually distributed — without distributing any rewards.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` once per block permanently destroys that block's reward allocation for every staker and every delegation pool in the protocol. Repeated across all blocks, this freezes all future unclaimed yield with no recovery path: the block numbers are consumed and can never be revisited.

---

### Likelihood Explanation

**High.** The function is fully public with no role restriction. `general_prerequisites` only asserts the contract is unpaused and the caller is non-zero. Any EOA or contract can call it. The attacker needs only a valid staker address (readable from on-chain events) and one transaction per block. There is no economic cost to the attacker beyond gas.

---

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards || self.is_pre_consensus()` guard, so the global slot is only consumed when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
// ... reward distribution logic ...
```

Alternatively, add an access-control check (e.g., `only_app_governor` or a dedicated sequencer role) so that only a trusted caller can invoke `update_rewards` with `disable_rewards = true`.

---

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` is set and current epoch ≥ that value).
2. Attacker observes any active staker address `S` from on-chain events.
3. At block `N`, attacker calls `update_rewards(S, disable_rewards: true)`.
   - `general_prerequisites()` passes (contract not paused, attacker ≠ 0).
   - `current_block_number (N) > last_reward_block` passes (first call this block).
   - Staker validity checks pass (S is active with non-zero balance).
   - `last_reward_block` is written to `N`.
   - Function returns early — zero rewards distributed.
4. Any legitimate staker or keeper that calls `update_rewards(any_staker, false)` at block `N` reverts with `REWARDS_ALREADY_UPDATED`.
5. Attacker repeats at block `N+1`, `N+2`, … — all block rewards are permanently lost. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L185-188)
```text
        staker_unstake_intent_epoch: Map<ContractAddress, Epoch>,
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1490)
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

```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
