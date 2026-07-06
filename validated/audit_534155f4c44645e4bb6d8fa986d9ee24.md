Looking at the analog vulnerability class from the report — **missing/bypassed access control on a critical state-mutating function** — I need to check whether `update_rewards` in the Starknet Staking codebase enforces its documented "Only starkware sequencer" access control.

The spec explicitly states:
> `update_rewards` — **access control: Only starkware sequencer.**

But the implementation at `src/staking/staking.cairo:1449-1488` has **no caller check at all**.

---

### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Staker Yield — (`File: src/staking/staking.cairo`)

### Summary
`update_rewards` is documented as callable only by the Starknet sequencer, but the implementation contains no such access control check. Any unprivileged address can call it with `disable_rewards: true` to consume the global `last_reward_block` slot for the current block, permanently preventing the sequencer from distributing rewards for that block to any staker or delegator.

### Finding Description
The `IStakingRewardsManager::update_rewards` function is the consensus-era reward distribution entry point. The spec at `docs/spec.md:1645` states its access control is "Only starkware sequencer." However, the implementation at `src/staking/staking.cairo:1449` performs only a `general_prerequisites()` check (pause guard) and a block-number deduplication guard — no caller identity check is present.

The deduplication guard is a **global** single-slot variable `last_reward_block` (storage field at `src/staking/staking.cairo:187`). Once any call to `update_rewards` succeeds in a given block, `last_reward_block` is written to that block number (`src/staking/staking.cairo:1485`), and all subsequent calls in the same block revert with `REWARDS_ALREADY_UPDATED`.

An attacker can therefore:
1. Monitor the mempool / block production.
2. At the start of every block, call `update_rewards(any_valid_staker, disable_rewards: true)`.
3. This passes all checks (staker exists, has balance, block is new), writes `last_reward_block = current_block`, and returns early without distributing any rewards (`src/staking/staking.cairo:1487-1488`).
4. When the sequencer's legitimate `update_rewards` call arrives in the same block, it reverts with `REWARDS_ALREADY_UPDATED`.

Rewards for that block are **permanently lost** — there is no catch-up mechanism. The `last_reward_block` guard is strictly `>`, so a missed block's rewards are simply never distributed.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Every block for which the attacker front-runs the sequencer call results in permanently lost rewards for all stakers and their delegators. The `_update_rewards` path that credits `unclaimed_rewards_own` and transfers STRK to pool contracts is never reached. Delegators' `cumulative_rewards_trace` is never updated for those blocks, so their `claim_rewards` will permanently under-count yield.

### Likelihood Explanation
**High.** The attack requires no capital, no privileged role, and no special setup. Any EOA can call `update_rewards` with a valid staker address and `disable_rewards: true`. The attacker only needs to submit a transaction before the sequencer's own system transaction in each block. On Starknet, where the sequencer is the block producer, this is a straightforward front-run or can be done by any node that can submit L2 transactions.

### Recommendation
Add a caller check at the top of `update_rewards` that restricts execution to the authorized sequencer address (stored in contract configuration), mirroring the pattern used by `update_rewards_from_attestation_contract` which calls `self.assert_caller_is_attestation_contract()`. A dedicated `sequencer_address` storage slot should be introduced and checked:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // <-- add this
    ...
}
```

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has passed).
2. Staker `S` exists with non-zero balance at the current epoch.
3. Attacker `A` (any address) calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. Execution path (`src/staking/staking.cairo:1452-1488`):
   - `general_prerequisites()` passes (not paused).
   - `current_block_number > last_reward_block` passes (new block).
   - Staker exists and is active — passes.
   - `last_reward_block.write(current_block_number)` — **slot consumed**.
   - `disable_rewards == true` → early return, zero rewards distributed.
5. Sequencer's legitimate call in the same block:
   - `current_block_number > last_reward_block` → **false** → reverts `REWARDS_ALREADY_UPDATED`.
6. All stakers and delegators receive zero rewards for this block. The loss is permanent. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1449-1488)
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
```

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
