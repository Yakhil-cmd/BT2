### Title
Caller-Controlled `disable_rewards` Parameter Allows Any Address to Advance Global `last_reward_block` Without Distributing Rewards — (`File: src/staking/staking.cairo`)

---

### Summary

`update_rewards` in `IStakingRewardsManager` is a public, permissionless function that accepts a caller-controlled `disable_rewards: bool` parameter. When set to `true`, the function advances the **global** `last_reward_block` storage variable to the current block number but skips all reward distribution. Because `last_reward_block` is global (not per-staker), any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`. An unprivileged attacker can call this every block to permanently deny all stakers their consensus block rewards.

---

### Finding Description

`update_rewards` is declared in the public `IStakingRewardsManager` interface with no access-control guard beyond `general_prerequisites()` (which only checks the contract is unpaused and the caller is non-zero):

```cairo
// src/staking/interface.cairo lines 303–311
pub trait IStakingRewardsManager<TContractState> {
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

Inside the implementation:

```cairo
// src/staking/staking.cairo lines 1448–1507
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks: unpaused + caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence / balance checks ...

    // ← GLOBAL state written unconditionally
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits WITHOUT distributing rewards
    }
    // ... reward distribution ...
}
``` [1](#0-0) 

The storage field `last_reward_block` is a single global value:

```cairo
// src/staking/staking.cairo line 187
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

The public interface exposes `disable_rewards` with no restriction on who may set it: [3](#0-2) 

---

### Impact Explanation

Every block the attacker calls `update_rewards(any_valid_active_staker, disable_rewards: true)`:

1. `last_reward_block` is advanced to the current block number.
2. No rewards are distributed to any staker or pool.
3. Every legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
4. The consensus block rewards for that block are **permanently lost** — they are never minted or credited to any staker.

Because the rewards for skipped blocks are never recoverable, this constitutes **permanent freezing of unclaimed yield** for all stakers and delegators across the entire protocol.

**Impact: High** — Permanent freezing of unclaimed yield.

---

### Likelihood Explanation

- The function is fully public and requires no special role, token ownership, or prior relationship with any staker.
- The attacker only needs to supply any currently active staker address (trivially obtained from on-chain events or `get_stakers()`).
- The cost is one transaction per block; on Starknet this is low.
- There is no profit motive required — a competitor, a griefing actor, or a protocol adversary can sustain this indefinitely.

**Likelihood: High** — Any unprivileged address can execute this every block at minimal cost.

---

### Recommendation

Remove the `disable_rewards` parameter from the public interface entirely, or restrict calls with `disable_rewards: true` to a trusted role (e.g., `security_agent` or `app_governor`). The simplest fix is to make `disable_rewards` an internal-only concern and expose only a no-argument public entry point that always distributes rewards:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress) {
    // ... no disable_rewards parameter ...
}
```

If `disable_rewards` must remain for administrative use (e.g., migration), gate it behind a role check:

```cairo
if disable_rewards {
    self.roles.only_security_agent();
}
```

---

### Proof of Concept

```
Precondition: Consensus rewards are active (is_pre_consensus() == false).
              At least one active staker with non-zero balance exists (e.g., `victim_staker`).

Attacker (any non-zero address) executes every block:

  staking_contract.update_rewards(
      staker_address: victim_staker,   // any valid active staker
      disable_rewards: true,           // caller-controlled, no access check
  );

Effect per block:
  - last_reward_block is set to current_block_number.
  - No rewards are distributed to any staker or pool.
  - Any subsequent call to update_rewards in the same block reverts
    with REWARDS_ALREADY_UPDATED.
  - Block rewards for this block are permanently lost.

After N blocks of continuous griefing:
  - All stakers have received 0 consensus block rewards.
  - The reward_supplier's unclaimed_rewards counter is never incremented.
  - Stakers' unclaimed_rewards_own fields remain at 0.
  - Pool cumulative_rewards_trace is never updated.
  - All yield for those N blocks is permanently unrecoverable.
```

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
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
