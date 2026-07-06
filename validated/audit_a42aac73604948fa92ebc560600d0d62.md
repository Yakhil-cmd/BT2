### Title
Unprivileged Caller Can Permanently Deny Block Rewards for All Stakers via Unvalidated `disable_rewards` Parameter - (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager::update_rewards` accepts a caller-supplied `disable_rewards: bool` parameter with no access control or on-chain validation. Any unprivileged address can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block, permanently consuming the global `last_reward_block` slot and preventing all stakers from receiving consensus block rewards for that block.

### Finding Description
`update_rewards` in `staking.cairo` is a publicly callable function that distributes per-block consensus rewards. It enforces a global once-per-block invariant via `last_reward_block`:

```
// line 1454-1457
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

Critically, `last_reward_block` is written **before** the `disable_rewards` branch is evaluated:

```
// line 1485
self.last_reward_block.write(current_block_number);

// line 1487-1489
if disable_rewards || self.is_pre_consensus() {
    return;
}
```

`disable_rewards` is a raw caller-supplied boolean. There is no check that the caller is the staker, the staker's operational address, the attestation contract, or any other trusted party. Any address can call:

```
update_rewards(staker_address: <any_active_staker>, disable_rewards: true)
```

This atomically:
1. Marks the current block as processed in the global `last_reward_block`.
2. Returns early, distributing zero rewards to any staker.

Because `last_reward_block` is a single global field (not per-staker), the slot is consumed for the entire block. No subsequent call to `update_rewards` in the same block can succeed — the `REWARDS_ALREADY_UPDATED` assertion will revert it.

### Impact Explanation
Every block in which an attacker front-runs the legitimate `update_rewards` call with `disable_rewards: true` results in **permanent, irrecoverable loss of block rewards** for all stakers and their delegators. The rewards that would have been minted and distributed for that block are simply never requested or allocated. This constitutes permanent freezing of unclaimed yield.

Impact: **High** — Permanent freezing of unclaimed yield for all stakers.

### Likelihood Explanation
The attack requires no special role, no capital, and no leaked key. Any EOA or contract can call `update_rewards` with `disable_rewards: true`. The attacker only needs to submit the transaction before the legitimate call in the same block (a standard front-run). On Starknet, transaction ordering within a block is determined by the sequencer, but the function is unconditionally open to any caller. The attack can be repeated every block at negligible cost (gas only), making sustained griefing economically viable.

Likelihood: **High**.

### Recommendation
Validate the `disable_rewards` parameter against on-chain state rather than accepting it blindly from the caller. Two concrete options:

1. **Remove the parameter entirely.** Derive the disable condition solely from on-chain state (e.g., staker's `unstake_time`, epoch state, or attestation status).
2. **Restrict the caller.** Gate `update_rewards` so that only the staker's registered operational address, the staker address itself, or the attestation contract may call it, and ignore or reject `disable_rewards: true` from any other source.

Either fix ensures the reward-suppression path cannot be triggered by an arbitrary unprivileged caller.

### Proof of Concept

1. Active staker `S` exists with non-zero STRK balance at the current epoch.
2. Attacker `A` (any address) monitors the mempool for the start of a new block.
3. `A` calls `update_rewards(staker_address: S, disable_rewards: true)`.
   - `general_prerequisites()` passes (contract not paused).
   - `current_block_number > last_reward_block` passes (new block).
   - `internal_staker_info(S)` succeeds (staker exists).
   - `is_staker_active(S, curr_epoch)` passes.
   - `staker_total_strk_balance.is_non_zero()` passes.
   - **`last_reward_block` is written to `current_block_number`.**
   - `disable_rewards == true` → early return, zero rewards distributed.
4. Any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers lose their block rewards for that block permanently.

Relevant code: [1](#0-0) [2](#0-1)

### Citations

**File:** src/staking/staking.cairo (L1185-1188)
```text
            );

            let to_staker_info = self.internal_staker_info(staker_address: to_staker);

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
