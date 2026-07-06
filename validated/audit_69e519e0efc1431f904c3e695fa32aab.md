### Title
Unrestricted `update_rewards` with `disable_rewards: true` Allows Any Caller to Grief All Stakers' Consensus Block Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable by any unprivileged address. It accepts a `disable_rewards: bool` parameter and unconditionally writes the current block number to the global `last_reward_block` storage slot — even when `disable_rewards: true` causes an early return with no rewards distributed. Because `last_reward_block` is a single global variable, only one successful call per block is possible. An attacker can front-run every legitimate block-proposer call with `disable_rewards: true`, permanently preventing all stakers from receiving consensus rewards.

---

### Finding Description

`update_rewards` is defined in `StakingRewardsManagerImpl` and is gated only by `general_prerequisites`, which checks that the contract is not paused and the caller is not the zero address:

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
    self.last_reward_block.write(current_block_number);   // ALWAYS written
    if disable_rewards || self.is_pre_consensus() {
        return;                                           // exits with no rewards
    }
    // ... reward distribution
}
``` [1](#0-0) 

The global `last_reward_block` is a single slot shared across all stakers:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

There is no check that the caller is the staker, the staker's operational address, or any privileged role. The `staker_address` argument is freely supplied by the caller.

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_active_staker, disable_rewards: true)` at the start of every block (or front-runs the legitimate proposer's transaction). The result:

1. `last_reward_block` is set to the current block number.
2. The function returns immediately — zero rewards are distributed.
3. Every subsequent call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
4. No staker receives consensus block rewards for that block.

Repeated across every block, this constitutes **permanent freezing of unclaimed yield** for all stakers and their delegators. The attacker gains nothing but the cost is only gas per block, which is negligible on Starknet.

**Allowed impact matched**: *High — Permanent freezing of unclaimed yield or unclaimed royalties.*

---

### Likelihood Explanation

- The function is fully public; no role, no signature, no stake requirement.
- The attacker only needs to know any one valid, active staker address (trivially obtained from on-chain events).
- The attack is a simple front-run or first-in-block transaction, executable by any EOA or contract.
- Gas cost on Starknet is low, making sustained griefing economically viable.

Likelihood: **High**.

---

### Recommendation

Restrict who may call `update_rewards`. The intended caller is the block proposer (or a sequencer-level mechanism). Enforce this by requiring the caller to be either:

- The staker's registered `operational_address`, or
- A designated consensus/sequencer contract.

Additionally, consider separating the `last_reward_block` update from the reward-distribution logic so that a `disable_rewards: true` call does not consume the block's reward slot for all other stakers.

---

### Proof of Concept

1. Staker `S` is active with non-zero balance. Attacker `A` is any address.
2. At block `N`, `A` submits `update_rewards(S, disable_rewards: true)` before `S`'s legitimate call.
3. Inside the function: `last_reward_block` is written to `N`; the function returns early.
4. `S` submits `update_rewards(S, disable_rewards: false)` — reverts with `REWARDS_ALREADY_UPDATED` because `N == last_reward_block`.
5. `S` (and every other staker) receives zero block rewards for block `N`.
6. `A` repeats step 2 at block `N+1`, `N+2`, … indefinitely.

The `general_prerequisites` check provides no barrier:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [3](#0-2) 

The only requirements are that the contract is unpaused and the caller is non-zero — both trivially satisfied by any attacker.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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
