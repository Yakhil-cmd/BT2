### Title
Global `last_reward_block` Consumed by Unprivileged `update_rewards(disable_rewards: true)` Call Freezes All Staker Rewards — (`src/staking/staking.cairo`)

---

### Summary

`update_rewards` is a publicly callable function that accepts a caller-controlled `disable_rewards` flag. The contract enforces a single-call-per-block invariant using a **global** `last_reward_block` storage variable. An unprivileged attacker can call `update_rewards` with `disable_rewards: true` at the start of every block, consuming the per-block slot without distributing any rewards, and causing `REWARDS_ALREADY_UPDATED` to revert every legitimate reward update for every staker in that block. Repeated across blocks, this permanently freezes all unclaimed yield in the post-consensus phase.

---

### Finding Description

**Root cause — global `last_reward_block` + public `disable_rewards` flag**

`IStakingRewardsManager::update_rewards` has no access-control restriction; the spec explicitly states "Any address can execute." [1](#0-0) 

Inside the implementation the function first checks that the current block is strictly greater than the stored `last_reward_block`, then **unconditionally writes the current block number back** before branching on `disable_rewards`: [2](#0-1) 

The critical sequence is:

```
assert!(current_block_number > self.last_reward_block.read(), REWARDS_ALREADY_UPDATED);
...
self.last_reward_block.write(current_block_number);   // ← slot consumed here

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← no rewards distributed
}
```

`last_reward_block` is a single contract-level storage slot, not a per-staker mapping. Once it is written to `current_block_number`, every subsequent call to `update_rewards` in the same block — regardless of which staker is targeted — reverts with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

**State-transition analogy to the reference bug**

The reference report describes a vault function whose state guard is too lenient (`settlementStatus != Defaulted` only), allowing a call on an already-terminal vault to revive it. Here the analogous leniency is: the "one update per block" guard checks only that the block number advanced, but does **not** restrict who may consume that slot or whether rewards must actually be distributed. An attacker exploits this by occupying the slot with `disable_rewards: true`, a state transition that is structurally valid (passes all checks) but semantically unauthorized (no rewards flow, yet the slot is marked used).

**Exploit path**

1. The post-consensus phase is active (`is_pre_consensus()` returns `false`).
2. Attacker observes any valid staker address `S` with non-zero STRK balance (publicly readable on-chain).
3. At the start of each new block, attacker submits:
   ```
   update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The call passes every check: contract unpaused, block advanced, staker active, balance non-zero.
5. `last_reward_block` is set to the current block; the function returns early — zero rewards distributed.
6. Any legitimate call to `update_rewards` for any staker in the same block reverts with `REWARDS_ALREADY_UPDATED`.
7. Repeated every block, no staker ever accumulates consensus-phase rewards. [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

All stakers and delegators in the post-consensus phase are denied rewards indefinitely. `unclaimed_rewards_own` never increases; `claim_rewards` returns zero. The attacker incurs only transaction fees and requires no privileged key, no governance access, and no token balance beyond gas.

---

### Likelihood Explanation

**High.** The entry point is fully public, requires no special role, and the precondition (any active staker with non-zero balance exists) is trivially satisfied on a live network. The attack is cheap to sustain (one transaction per block) and is immediately effective from the first block of the consensus phase.

---

### Recommendation

1. **Restrict `disable_rewards`** to a privileged role (e.g., security agent or governance), or remove the parameter from the public interface entirely.
2. **Make `last_reward_block` per-staker** (a `Map<ContractAddress, BlockNumber>`) so that one staker's update cannot block another's.
3. If a global slot is intentional for gas reasons, gate the write behind a successful reward distribution: only advance `last_reward_block` when `disable_rewards` is `false` and rewards are actually computed and transferred.

---

### Proof of Concept

```
// Precondition: consensus phase active, staker S exists with non-zero balance.
// Attacker runs this at the start of every block:

let staking = IStakingRewardsManagerDispatcher { contract_address: staking_contract };

loop {
    // wait for new block N
    staking.update_rewards(staker_address: S, disable_rewards: true);
    // last_reward_block == N; no rewards distributed.
    // Any legitimate update_rewards call for any staker in block N now reverts.
}

// After K blocks: all stakers have unclaimed_rewards_own == 0.
// claim_rewards() returns 0 for every staker.
```

### Citations

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

**File:** src/staking/staking.cairo (L1449-1490)
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
