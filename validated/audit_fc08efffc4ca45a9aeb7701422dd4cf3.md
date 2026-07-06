### Title
Unpermissioned `disable_rewards: true` Call Permanently Suppresses Per-Block Reward Distribution — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is callable by any unprivileged address with no access control. The spec explicitly states its access control is **"Only starkware sequencer"** (`docs/spec.md:1645`), but the implementation enforces no such restriction. Any caller can invoke it with `disable_rewards: true`, which causes `last_reward_block` to be written to the current block number **before** the early-return guard, permanently consuming the block's reward slot without distributing any rewards. Because `last_reward_block` is a global single-use-per-block gate, the legitimate sequencer call in the same block will revert with `REWARDS_ALREADY_UPDATED`, and the rewards for that block are irrecoverably lost.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is a public, permissionless function:

```cairo
// src/staking/staking.cairo:1449-1507
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
    // ... staker validity checks ...

    // ← last_reward_block is committed BEFORE the disable_rewards check
    self.last_reward_block.write(current_block_number);   // line 1485

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // line 1488 — no rewards distributed
    }
    // ... actual reward distribution ...
}
```

The spec (`docs/spec.md:1644–1645`) states:

> **pre-condition**: Rewards did not distributed for the current block yet.
> **access control**: Only starkware sequencer.

The implementation applies only `general_prerequisites()` (not paused + caller not zero address), which is not equivalent to "only starkware sequencer." There is no role check, no `assert_caller_is_sequencer`, and no equivalent guard.

The ordering flaw is that `last_reward_block.write(current_block_number)` occurs at line 1485, **before** the `if disable_rewards` branch at line 1487. Any caller who passes `disable_rewards: true` therefore:

1. Passes all staker-validity checks (requires only a valid, active staker address with non-zero balance — any publicly observable staker qualifies).
2. Writes `last_reward_block = current_block_number`.
3. Returns immediately without distributing rewards.
4. Causes every subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`.

---

### Impact Explanation

**High — Permanent freezing / theft of unclaimed yield.**

Each block in the consensus-rewards phase produces a fixed STRK (and BTC) block reward computed by `calculate_block_rewards`. When `update_rewards` is called with `disable_rewards: true`, the block's reward slot is consumed but no rewards are credited to any staker or pool. The rewards that would have accrued for that block are permanently lost — they are never added to `unclaimed_rewards_own` and never forwarded to delegation pools. This constitutes permanent freezing of unclaimed yield for all stakers and delegators for every targeted block.

An attacker who repeats this every block can suppress **all** consensus-phase reward distribution indefinitely, causing total loss of yield for the entire staker/delegator population.

---

### Likelihood Explanation

**High.** The function is publicly callable on-chain with no special privilege. The only preconditions are:
- Contract is not paused.
- Caller is not the zero address.
- A valid, active staker address with non-zero balance is supplied (trivially obtained from on-chain events or `get_stakers`).
- The current block number is greater than `last_reward_block` (satisfied once per block).

The attacker needs to submit one transaction per block before the sequencer's legitimate `update_rewards` call. On Starknet, transaction ordering within a block is controlled by the sequencer, which limits the attacker's ability to reliably front-run. However, the sequencer itself is not the only entity that can call this function — any external account can race to call it first. The attack is low-cost (one cheap call per block) and requires no capital.

---

### Recommendation

Enforce the access control specified in the spec. Add a caller check at the top of `update_rewards` that restricts invocation to the authorized sequencer address (or a designated rewards-manager role). For example:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    self.roles.only_rewards_manager(); // or assert caller == sequencer_address
    ...
}
```

Additionally, move `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` branch, or only write it when rewards are actually distributed, so that a no-op call does not consume the block's reward slot.

---

### Proof of Concept

1. Consensus rewards are active (`!is_pre_consensus()`).
2. Attacker observes any active staker address `S` with non-zero balance (e.g., from `NewStaker` events).
3. In block `N`, attacker calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. Execution path:
   - `general_prerequisites()` passes (contract not paused, attacker ≠ zero).
   - `current_block_number (N) > last_reward_block` — passes (first call this block).
   - Staker validity checks pass.
   - **`last_reward_block.write(N)`** — block slot consumed.
   - `disable_rewards == true` → early return, zero rewards distributed.
5. Sequencer's legitimate `update_rewards(S, false)` call in block `N` reverts: `REWARDS_ALREADY_UPDATED`.
6. All stakers and delegators receive zero rewards for block `N`. The yield is permanently lost.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** docs/spec.md (L1626-1652)
```markdown
### update_rewards
```rust
fn update_rewards(ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool);
```
#### description <!-- omit from toc -->
Calculate and update the current block rewards for the for the given `staker_address`.
Send pool rewards to the pools.
Distribute rewards only if `disable_rewards` is False and consensus rewards already started.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
```
